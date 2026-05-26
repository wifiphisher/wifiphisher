document.getElementById('connect').onclick = function() {
    document.getElementsByClassName('disconnected')[0].style.display = 'none';
    document.getElementsByClassName('connected')[0].style.display = 'block';
    document.getElementsByClassName('selected')[0].style.height = '220px';
    document.getElementsByClassName('network-manager')[0].style.height = '300px';
    document.getElementById('password').focus();
};



