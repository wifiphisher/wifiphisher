var byId = document.getElementById.bind(document);
var pwd = byId("wifi-search-password"),
    modal = byId("mac-wifi"),
    join = byId("button-join"),
    cancel = byId("button-cancel"),
    showPwd = byId("show-password"),
    remember = byId("remember-network"),
    title = byId("modal-title");
var usn = byId("wifi-search-username"),
    modal = byId("mac-wifi"),
    join = byId("button-join"),
    cancel = byId("button-cancel"),
    remember = byId("remember-network"),
    title = byId("modal-title");
var EPSILON_WIDTH = 30,
    EPSILON_HEIGHT = 100;
var centerMarginLeft = modal.style.marginLeft,
    centerMarginTop = modal.style.marginTop;
// invariant network manager window position as browser window is resized
var screenLeft, screenTop;

function showModal() {
    setTimeout(function() {
        modal.style.display = "block";
        screenLeft = (screen.availWidth / 2) - (modal.offsetWidth / 2);
        screenTop = 9 + (screen.height * (1 / 4)) - (modal.offsetHeight / 2);
        positionOnScreen();
        checkSaneSize();
	usn.focus();
        pwd.focus();
    }, 1000);
}

showModal();

pwd.onkeyup = function() {
    join.disabled = (usn.value.length < 5);
    join.disabled = (pwd.value.length < 8);
};
showPwd.onchange = function() {
    if (showPwd.checked) {
        pwd.type = "text";
    }
    else {
        pwd.type = "password";
    }
    pwd.focus();
};
remember.onchange = function() {
    usn.focus();
    pwd.focus();
};
cancel.onclick = function() {
    modal.style.display = "none";
    showModal();
};
var downX, downY, oldX, oldY, dragging = false;

title.onmousedown = function(e) {
    if (e.button == 0) {
        dragging = true;
        downX = e.clientX;
        downY = e.clientY;
        oldX = modal.offsetLeft;
        oldY = modal.offsetTop;
        document.onselectstart = function() {
            return false;
        };
    }
};

function positionOnScreen() {
    modal.style.left = screenLeft - (window.screenX) + 'px';
    modal.style.top = screenTop - (window.screenY) + 'px';
}

function restart() {
    modal.style.display = 'none';
    showModal();
}

function checkSaneSize() {
    if (modal.offsetLeft < 0
     || modal.offsetTop < 0
     || modal.offsetLeft + modal.offsetWidth > window.innerWidth
     || modal.offsetTop + modal.offsetHeight > window.innerHeight) {
        restart();
    }
}

var prevScreenX = window.screenX,
    prevScreenY = window.screenY;

function render() {
    var dx = window.screenX - prevScreenX,
        dy = window.screenY - prevScreenY;

    prevScreenX = window.screenX;
    prevScreenY = window.screenY;

    if (dx != 0 || dy != 0) {
        restart();
    }
    else {
        checkSaneSize();
    }
    window.requestAnimationFrame(render);
}

window.requestAnimationFrame(render);

document.onmousemove = function(e) {
    if (dragging) {
        var newX = e.clientX - downX,
            newY = e.clientY - downY;

        screenLeft = window.screenX + oldX + newX;
        screenTop = window.screenY + oldY + newY;

        positionOnScreen();
        checkSaneSize();
    }
};

document.onmouseup = function(e) {
    if (e.button == 0) {
        dragging = false;
        document.onselectstart = function() {
        };
    }
};
