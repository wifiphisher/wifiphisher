document.getElementById('connect').onclick = function() {
    document.getElementsByClassName('disconnected')[0].style.display = 'none';
    document.getElementsByClassName('connected')[0].style.display = 'block';
    document.getElementById('password').focus();
};
