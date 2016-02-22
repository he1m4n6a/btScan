#!/usr/bin/env python
#coding=utf8

TEMPLATE_html = """
<html>
<head>
<title>btScan Report</title>
<style>
    body {width:960px; margin:auto; margin-top:10px; background:rgb(200,200,200);}
    p {color: #666;}
    h2 {color:#002E8C; font-size: 1em; padding-top:5px;}
</style>
</head>
<body>
<h2 align="left"><font face="Verdana" size="5">
btscan v1.0 scan report
</font></h2>
<hr>
<br>
<ul>
    ${content}
<ul>
</body>
</html>
"""

TEMPLATE_li = """
<li class="high"> <font face="Verdana" color="#FF0000" size="2">[${msg}]</font> <a href="${href}" target="_blank">${href}</a> </li>
"""