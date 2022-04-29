'use strict';

(() => {
    document.addEventListener('DOMContentLoaded', (_) => {
        const waiting = false;
        let xhr;

        const field = document.getElementById('url');

        field.addEventListener('change', () => {
            if (waiting && xhr != null) {
                xhr.abort();
            }
        });
        
        const form = document.getElementById('form');

        form.addEventListener('submit', (event) => {
            // We need to create a different body, so prevent the default submission.
            event.preventDefault();

            if (waiting) {
                // Prevent multiple requests.
                return;
            }

            // Get the URL the user is trying to shorten.
            const url = document.getElementById('url').value;

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
                switch (xhr.status) {
                    case 200:
                        let slug = xhr.response;
                        console.log(slug);
                    break;
                    default:
                        console.log(xhr.response);
                    break;
                }
            };
            xhr.onerror = () => {
                // TODO
            };
        });
    });
})();