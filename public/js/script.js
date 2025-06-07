// script.js - Enhanced scroll behavior for fixed navbar & other UI enhancements
document.addEventListener("DOMContentLoaded", () => {
  const navbar = document.querySelector('.navbar-custom');
  const scrollLinks = document.querySelectorAll('a.nav-link[href^="#"]');
  const API_BASE_URL_PUBLIC = ''; // Relative for public page API calls

  const getNavbarHeight = () => navbar ? navbar.offsetHeight : 0;

  const smoothScroll = (e) => {
    e.preventDefault();
    const href = e.currentTarget.getAttribute('href');
    if (href && href.length > 1 && href.startsWith('#')) {
        const targetId = href.substring(1);
        const target = document.getElementById(targetId);
        if (target) {
          const navbarHeight = getNavbarHeight();
          const targetPosition = target.getBoundingClientRect().top + window.pageYOffset;
          const offsetPosition = targetPosition - navbarHeight;
          window.scrollTo({ top: offsetPosition, behavior: 'smooth' });
          
          const navbarToggler = navbar?.querySelector('.navbar-toggler');
          const navbarCollapse = navbar?.querySelector('.navbar-collapse');
          if (navbarToggler && navbarCollapse?.classList.contains('show') && getComputedStyle(navbarToggler).display !== 'none') {
             const bsCollapse = bootstrap.Collapse.getInstance(navbarCollapse) || new bootstrap.Collapse(navbarCollapse, { toggle: false });
             bsCollapse.hide();
          }
        }
    }
  };

  scrollLinks.forEach(link => link.addEventListener('click', smoothScroll));

  if (window.location.hash && window.location.hash.length > 1) {
    const targetId = window.location.hash.substring(1);
    const target = document.getElementById(targetId);
    if (target) {
      setTimeout(() => {
        const navbarHeight = getNavbarHeight();
        const targetPosition = target.getBoundingClientRect().top + window.pageYOffset;
        const offsetPosition = targetPosition - navbarHeight;
        window.scrollTo({ top: offsetPosition, behavior: 'auto' });
      }, 300); // Increased timeout for dynamic content
    }
  }

  const revealElements = document.querySelectorAll('.reveal, .reveal-left, .reveal-right');
  const observerOptions = { root: null, rootMargin: '0px', threshold: 0.1 };
  const revealObserver = new IntersectionObserver((entries, observer) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('active');
        observer.unobserve(entry.target);
      }
    });
  }, observerOptions);
  revealElements.forEach(el => revealObserver.observe(el));

  const sections = document.querySelectorAll('section[id]');
  const navLi = document.querySelectorAll('.navbar-nav .nav-item .nav-link');
  window.addEventListener('scroll', () => {
    let current = '';
    const navbarHeight = getNavbarHeight() + 30; // Increased offset
    sections.forEach(section => {
      const sectionTop = section.offsetTop - navbarHeight;
      if (pageYOffset >= sectionTop && pageYOffset < sectionTop + section.clientHeight) {
        current = section.getAttribute('id');
      }
    });
    if (window.innerHeight + window.pageYOffset >= document.body.offsetHeight - 5 && sections.length > 0) {
        current = sections[sections.length -1].getAttribute('id');
    }
    navLi.forEach(link => {
      link.classList.remove('active');
      const href = link.getAttribute('href');
      if (href && href.substring(1) === current) link.classList.add('active');
    });
    if (sections.length > 0 && pageYOffset < sections[0].offsetTop - navbarHeight) {
        navLi.forEach(link => link.classList.remove('active'));
        const homeLink = document.querySelector('.navbar-nav .nav-item .nav-link[href="#hero"]');
        if (homeLink) homeLink.classList.add('active');
    }
  }, { passive: true }); // Added passive for performance

  // --- Contact Form Submission Handler (Public Page) ---
  const contactForm = document.getElementById('mainContactForm');
  const contactFormStatusDiv = document.getElementById('contactFormStatus');
  const contactSubmitButton = contactForm ? contactForm.querySelector('button[type="submit"]') : null;

  if (contactForm && contactSubmitButton && contactFormStatusDiv) {
    contactForm.addEventListener('submit', async function (event) {
      event.preventDefault();
      if (!contactForm.checkValidity()) {
        event.stopPropagation();
        contactForm.classList.add('was-validated');
        contactFormStatusDiv.innerHTML = `<div class="alert alert-warning" role="alert">Please fill out all required fields.</div>`;
        return;
      }
      contactForm.classList.add('was-validated');

      const formData = new FormData(contactForm);
      const data = {};
      formData.forEach((value, key) => { data[key] = value; });

      const originalButtonText = contactSubmitButton.innerHTML;
      contactSubmitButton.disabled = true;
      contactSubmitButton.innerHTML = 'Sending... <span class="spinner-border spinner-border-sm"></span>';
      contactFormStatusDiv.innerHTML = '';

      try {
        const response = await fetch(`${API_BASE_URL_PUBLIC}/api/submit-contact`, { // Added /api prefix
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(data),
        });
        const result = await response.json();

        if (response.ok && result.success) {
          if (result.action === 'whatsapp' && result.whatsappUrl) {
            contactFormStatusDiv.innerHTML = `<div class="alert alert-info" role="alert">${result.message || 'Redirecting to WhatsApp...'}</div>`;
            window.location.href = result.whatsappUrl;
            // Button will remain disabled as page redirects
          } else if (result.action === 'email') {
            contactFormStatusDiv.innerHTML = `<div class="alert alert-success" role="alert">${result.message || 'Message sent successfully!'}</div>`;
            contactForm.reset();
            contactForm.classList.remove('was-validated');
            contactSubmitButton.disabled = false;
            contactSubmitButton.innerHTML = originalButtonText;
          } else {
            contactFormStatusDiv.innerHTML = `<div class="alert alert-warning" role="alert">${result.message || 'Request processed, action unclear.'}</div>`;
            contactSubmitButton.disabled = false;
            contactSubmitButton.innerHTML = originalButtonText;
          }
        } else {
          contactFormStatusDiv.innerHTML = `<div class="alert alert-danger" role="alert">${result.message || 'An error occurred. Please try again.'}</div>`;
          contactSubmitButton.disabled = false;
          contactSubmitButton.innerHTML = originalButtonText;
        }
      } catch (error) {
        console.error('Error submitting contact form:', error);
        contactFormStatusDiv.innerHTML = `<div class="alert alert-danger" role="alert">A network error occurred. Please try again.</div>`;
        contactSubmitButton.disabled = false;
        contactSubmitButton.innerHTML = originalButtonText;
      }
    });
  }

  // Bootstrap validation standard init (if not already done inline in HTML)
  const formsNeedingValidation = document.querySelectorAll('.needs-validation');
  Array.from(formsNeedingValidation).forEach(form => {
    if (form.id !== 'mainContactForm') { // Avoid double-binding if mainContactForm already handled
        form.addEventListener('submit', event => {
          if (!form.checkValidity()) {
            event.preventDefault();
            event.stopPropagation();
          }
          form.classList.add('was-validated');
        }, false);
    }
  });

  // Dynamic year
  const currentYearElements = document.querySelectorAll('[data-current-year]');
  const nextYearElements = document.querySelectorAll('[data-next-year]');
  const currentYear = new Date().getFullYear();
  currentYearElements.forEach(el => el.textContent = currentYear);
  nextYearElements.forEach(el => el.textContent = currentYear + 1);

});