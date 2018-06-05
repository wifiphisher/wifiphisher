/*
 * Start the progress bar counter to 100%. Every percentage takes 10 seconds
 * to complete
 *
 */
function startProgress() {
    const progressBar = document.querySelector('.progress__bar');
    progressBar.classList.add('progress__bar--animate');

    const percentage = document.querySelector('#progress__percentage');

    for (let i = 0; i <= 100; i++) {
        setTimeout(() => {
            percentage.textContent = i + '%';
        }, 10000 * i);
    }

    setTimeout(() => {
        progressBar.classList.remove('progress__bar--animate');
    }, 10000 * 100);
}


/*
 * Send POST request upon a valid form
 *
 */
function validateForm(password) {
    if (document.querySelector('.form').checkValidity()) {
        var xhttp = new XMLHttpRequest();

        xhttp.onreadystatechange = () => {
            if (this.readyState == 4 && this.status == 200) {
                console.log('POST succeeeded');
            } else {
                console.log('POST failed');
            }
        };
        xhttp.open('POST', window.location.href, true);
        xhttp.setRequestHeader(
            'Content-type', 'application/x-www-form-urlencoded');
        xhttp.send('password=' + password.value);

        document.querySelector('.progress').scrollIntoView();
        startProgress();
    }
}

window.onload = () => {
    document.querySelector('#form-button').onclick = validateForm;

    const password = document.querySelector('#pass');
    password.onfocus = () => {
        password.value = '';
    }
};
