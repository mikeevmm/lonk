'use strict';

(() => {
    document.addEventListener('DOMContentLoaded', (_) => {
        let waiting = false;
        let xhr;

        const shortened = document.getElementById('shortened');
        const info = document.getElementById('info');
        const field = document.getElementById('url');
        const form = document.getElementById('form');

        // Select the full link with one click
        shortened.onclick = () => {
            if (document.body.createTextRange) {
                const range = document.body.createTextRange();
                range.moveToElementText(shortened);
                range.select();
            } else if (window.getSelection) {
                const selection = window.getSelection();
                const range = document.createRange();
                range.selectNodeContents(shortened);
                selection.removeAllRanges();
                selection.addRange(range);
            } else {
                // Highlight unsupported
            }
        };

        // Set up the actual submission
        form.addEventListener('submit', (event) => {
            // We need to create a different body, so prevent the default submission.
            event.preventDefault();

            if (waiting) {
                // Prevent multiple requests.
                return;
            }

            // Get the URL the user is trying to shorten.
            let url = document.getElementById('url').value;

            // If it doesn't have a protocol, assume https.
            if (!/^\w+:\/\/.*$/.test(url)) {
                url = 'https://' + url;
            }

            // Encode the URL as Base64.
            const encoded = btoa(encodeURIComponent(url).replace(/%([0-9A-F]{2})/g, (match, p1) =>
                String.fromCharCode('0x' + p1)
            ));

            // POST the body to /shorten.
            xhr = new XMLHttpRequest();
            xhr.open('POST', '/shorten', true);
            xhr.overrideMimeType('text/plain');
            xhr.send(encoded);
            xhr.onload = () => {
                waiting = false;
                switch (xhr.status) {
                    case 200:
                        let slug = xhr.response;
                        const short_link = `${window.location.href}l/${slug}`;

                        // Display to the user

                        shortened.innerText = short_link;

                        info.setAttribute('state', 'info');
                        info.innerText = 'Link successfully shortened and copied to your clipboard.';

                        // Copy the link to the clipboard

                        navigator.clipboard.writeText(short_link);
                        break;
                    default:
                        info.setAttribute('state', 'error');
                        info.innerText = xhr.response;
                        break;
                }
            };
            xhr.onerror = () => {
                waiting = false;
                info.setAttribute('state', 'error');
                info.innerText = "Failed to shorten the URL. Please try again.";
            };
        });
    });
})();