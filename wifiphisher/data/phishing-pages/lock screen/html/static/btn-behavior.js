document.getElementById('btn').onclick = function() {
var containerElement = document.getElementById('page1');
containerElement.setAttribute('class', 'blur');
/*
document.getElementsByClassName("page1")[0].style.filter = 'blur(5px);';
document.getElementsByTagName("page1")[0].style.filter = 'blur(5px);';
*/
};