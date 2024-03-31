        const form = document.getElementById('contactForm');
        const submitButton = document.getElementById('submitButton');
  
        // Function to check if all required fields are filled in
        function checkFormValidity() {
          const requiredInputs = form.querySelectorAll('[data-sb-validations="required"]');
          let allFilled = true;
          requiredInputs.forEach(input => {
            if (!input.value.trim()) {
              allFilled = false;
            }
          });
          return allFilled;
        }
  
        // Add event listener to the form fields to check validity
        form.addEventListener('input', () => {
          if (checkFormValidity()) {
            submitButton.removeAttribute('disabled');
          } else {
            submitButton.setAttribute('disabled', 'disabled');
          }
        });