#pragma once

static const char *tmpl_blog_info = \
        "<div class='post-preview'>" \
        "  <a href='/blogs/%d'>"\
        "  <h2 class='post-title'>%s</h2>" \
        "  <h3 class='post-subtitle'>%s</h3>"\
        "  </a>" \
        "  <p class='post-meta'>Posted by <a href='%s'>%s</a> on %s</p>"\
        "</div>"\
        "<hr>";

static const char *tmpl_blog = \
    "<header class='intro-header' style=\"background-image: url('/img/post-bg.jpg')\">"\
    "    <div class='container'>"\
    "        <div class='row'>"\
    "                <div class='col-lg-8 col-lg-offset-2 col-md-10 col-md-offset-1'>"\
    "                    <div class='post-heading'>"\
    "                    <h1>%s</h1>"\
    "                    <h2 class='subheading'>%s</h2>"\
    "                    <span class='meta'>Posted by <a href='%s'>%s</a> on %s</span>"\
    "                </div>"\
    "            </div>"\
    "        </div>"\
    "    </div>"\
    "</header>"\
    "<article>"\
    "    <div class='container'>"\
    "        <div class='row'>"\
    "            <div class='col-lg-8 col-lg-offset-2 col-md-10 col-md-offset-1'>"\
    "%s"\
    "</div></div></div></article><hr>";




