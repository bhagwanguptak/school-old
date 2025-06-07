// admin.js - Manages admin panel and dynamic content updates for school.html

const API_BASE_URL = ''; // Relative path, so it works with any host/port
const MAX_FACILITY_CARDS = 6;

// CKEditor instances
let aboutUsTextEditorInstance;
let academicsEditorInstance;
let admissionEditorInstance;
let facilitiesTextEditorInstance;

// Helper function to safely get elements
function getElement(id) { return document.getElementById(id); }
function querySelector(selector) { return document.querySelector(selector); }
function querySelectorAll(selector) { return document.querySelectorAll(selector); }

// Initialize CKEditor
async function initializeEditors() {
  try {
    const editorConfig = {
        toolbar: [ 'heading', '|', 'bold', 'italic', 'link', 'bulletedList', 'numberedList', 'removeFormat', '|', 'undo', 'redo' ],
        // Ensure CKEditor content styles match your site or are neutral
        // contentsCss: ["/css/style.css"] // Example if you want it to look like the site
    };
    if (getElement('aboutUsTextEditor')) {
        aboutUsTextEditorInstance = await ClassicEditor.create(getElement('aboutUsTextEditor'), editorConfig);
    }
    if (getElement('academics-editor')) {
      academicsEditorInstance = await ClassicEditor.create(getElement('academics-editor'), editorConfig);
    }
    if (getElement('admission-editor')) {
      admissionEditorInstance = await ClassicEditor.create(getElement('admission-editor'), editorConfig);
    }
    if (getElement('facilitiesTextEditor')) {
        facilitiesTextEditorInstance = await ClassicEditor.create(getElement('facilitiesTextEditor'), editorConfig);
    }
  } catch (error) {
    console.error('Error initializing CKEditor:', error);
  }
}

function generateFacilityCardInputsAdmin(facilityCardsData = []) {
    const container = getElement('facilityCardsAdminContainer');
    if (!container) return;
    const existingP = container.querySelector('p.text-muted');
    container.innerHTML = '';
    if (existingP) container.appendChild(existingP);

    for (let i = 0; i < MAX_FACILITY_CARDS; i++) {
        const cardData = facilityCardsData[i] || { iconClass: '', title: '', description: '' };
        const cardDiv = document.createElement('div');
        cardDiv.className = 'facility-card-admin mb-3 p-3 border rounded';
        cardDiv.innerHTML = `
            <h5>Facility Card ${i + 1}</h5>
            <div class="mb-2">
                <label for="facilityIcon${i}" class="form-label small">Icon Class (e.g., bi-building-gear)</label>
                <input type="text" id="facilityIcon${i}" class="form-control form-control-sm" value="${cardData.iconClass || ''}" placeholder="bi-building-gear">
            </div>
            <div class="mb-2">
                <label for="facilityTitle${i}" class="form-label small">Title</label>
                <input type="text" id="facilityTitle${i}" class="form-control form-control-sm" value="${cardData.title || ''}" placeholder="Card Title">
            </div>
            <div class="mb-2">
                <label for="facilityDesc${i}" class="form-label small">Description</label>
                <textarea id="facilityDesc${i}" class="form-control form-control-sm" rows="2" placeholder="Short description">${cardData.description || ''}</textarea>
            </div>
        `;
        container.appendChild(cardDiv);
    }
}

async function fetchSettings() {
  try {
    const response = await fetch(`${API_BASE_URL}/api/settings`); // Added /api prefix
    if (!response.ok) {
        const responseText = await response.text();
        console.error(`FETCH SETTINGS FAILED: Server responded with ${response.status}. Body:\n`, responseText);
        // Attempt to parse JSON if it's an auth error from our improved checkAuth
        if (response.status === 401 || response.status === 403) {
            try {
                const errorJson = JSON.parse(responseText);
                if (errorJson.redirectTo) {
                    alert('Session expired. Please log in again.');
                    window.location.href = errorJson.redirectTo;
                    return null; // Prevent further processing
                }
            } catch (e) { /* Not a JSON error message from checkAuth */ }
        }
        throw new Error(`Network response was not ok (${response.status}) when fetching settings. Check console.`);
    }
    const serverSettings = await response.json();
    
    const defaults = {
      schoolName: '', defaultHeroTitle: 'Welcome to Our School', schoolTagline: '', defaultHeroTagline: 'Nurturing Future Leaders',
      logoURL: '', defaultLogoURL: '/uploads/logo-default.png',
      aboutUsImageURL: '', defaultAboutImageURL: '/uploads/about-us-default.jpg',
      academicsImageURL: '', defaultAcademicsImageURL: '/uploads/academics-default.jpg',
      schoolFont: "'Poppins', sans-serif", schoolTheme: 'light',
      aboutUsText: '<p>Default About Us. Configure in admin.</p>',
      academics: '<p>Default Academics. Configure in admin.</p>',
      admission: '<p>Default Admissions. Configure in admin.</p>',
      facilitiesText: '<p>Default Facilities Overview. Configure in admin.</p>',
      socialLinks: { facebook: '', twitter: '', instagram: '', linkedin: '', youtube: '' },
      socialWhatsapp: '', contactMapEmbedURL: '',
      facilityCards: Array(MAX_FACILITY_CARDS).fill({ iconClass: '', title: '', description: '' }),
      aboutGradient: { color1: '#e0c3fc', color2: '#8ec5fc', color3: '#000000', color4: '#000000', direction: 'to right' },
      admissionsGradient: { color1: '#007bff', color2: '#6f42c1', color3: '#000000', color4: '#000000', direction: '135deg' },
      academicsGradient: { color1: '#f8f9fa', color2: '#e9ecef', color3: '#000000', color4: '#000000', direction: 'to bottom right' },
      facilitiesGradient: { color1: '#f8f9fa', color2: '#ffffff', color3: '#000000', color4: '#000000', direction: 'to right' },
      contactGradient: { color1: '#ffffff', color2: '#e9ecef', color3: '#000000', color4: '#000000', direction: 'to right' },
      heroGradient: { color1: '#007bff', color2: '#6f42c1', color3: '#fd7e14', color4: '#00c6ff', direction: '45deg'},
      defaultCarouselImageURL: '/uploads/placeholder-carousel.jpg',
      defaultCarouselAltText: 'Our Beautiful Campus', defaultCarouselLink: '#about',
      contactFormAction: 'whatsapp', schoolContactEmail: '', adminSchoolWhatsappNumber: ''
    };

    const completeSettings = { 
        ...defaults, 
        ...serverSettings,
        socialLinks: { ...defaults.socialLinks, ...(serverSettings.socialLinks || {}) },
        facilityCards: Array.isArray(serverSettings.facilityCards) && serverSettings.facilityCards.length > 0 
            ? serverSettings.facilityCards.map(card => ({ ...{ iconClass: '', title: '', description: '' }, ...card })).slice(0, MAX_FACILITY_CARDS)
            : defaults.facilityCards,
        aboutGradient: { ...defaults.aboutGradient, ...(serverSettings.aboutGradient || {}) },
        admissionsGradient: { ...defaults.admissionsGradient, ...(serverSettings.admissionsGradient || {}) },
        academicsGradient: { ...defaults.academicsGradient, ...(serverSettings.academicsGradient || {}) },
        facilitiesGradient: { ...defaults.facilitiesGradient, ...(serverSettings.facilitiesGradient || {}) },
        contactGradient: { ...defaults.contactGradient, ...(serverSettings.contactGradient || {}) },
        heroGradient: { ...defaults.heroGradient, ...(serverSettings.heroGradient || {}) }
    };
    
    if (completeSettings.facilityCards.length < MAX_FACILITY_CARDS) {
        const diff = MAX_FACILITY_CARDS - completeSettings.facilityCards.length;
        for (let i = 0; i < diff; i++) {
            completeSettings.facilityCards.push({ iconClass: '', title: '', description: '' });
        }
    }
    return completeSettings;
  } catch (error) {
    console.error('Error fetching settings:', error.message);
    // If error already handled by auth check, no need for another alert
    if (!error.message.toLowerCase().includes('session expired')) {
        alert('Failed to load initial settings. Some defaults might be used. Check console.');
    }
    // Return defaultsOnError if fetch fails for other reasons
    const defaultsOnError = { /* ... copy from above defaults ... */ };
    return JSON.parse(JSON.stringify(defaultsOnError));
  }
}

async function saveSettingsToServer(settingsToSave) {
  try {
    console.log(`Attempting to save settings to ${API_BASE_URL}/api/settings`);
    const response = await fetch(`${API_BASE_URL}/api/settings`, { // Added /api prefix
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ settings: settingsToSave })
    });

    console.log('Response Status:', response.status);
    const contentType = response.headers.get('Content-Type');
    console.log('Response Content-Type:', contentType);

    if (!response.ok) {
      const responseText = await response.text();
      if (response.status === 401 || response.status === 403) {
        console.error('SAVE SETTINGS FAILED: Authentication error. Status:', response.status);
        try {
            const errorJson = JSON.parse(responseText);
            if (errorJson.redirectTo) {
                alert(errorJson.error || 'Your session has expired. Please log in again.');
                window.location.href = errorJson.redirectTo;
                throw new Error('Authentication failed. Redirecting...');
            }
        } catch(e) { /* Not our specific JSON error */ }
        alert('Authentication error. Please log in again.');
        window.location.href = '/login.html?sessionExpired=true'; // Fallback redirect
        throw new Error('Authentication failed.');
      } else {
        console.error(`SAVE SETTINGS FAILED: Server responded with ${response.status}. Body:\n`, responseText);
        let errorDetail = `Failed to save settings. Server responded with ${response.status}.`;
        if (contentType && contentType.includes("application/json")) {
            try { const errorJson = JSON.parse(responseText); errorDetail = errorJson.message || JSON.stringify(errorJson); } catch (e) { /* ignore */ }
        } else if (contentType && contentType.includes("text/html")) {
            errorDetail = `Server returned an HTML error page (status ${response.status}). Check server logs.`;
        }
        throw new Error(errorDetail);
      }
    }

    if (contentType && contentType.includes("application/json")) {
        const result = await response.json();
        console.log('Settings saved successfully on server:', result);
        return result;
    } else {
        console.warn('SAVE SETTINGS WARNING: Server response was OK, but not JSON. Content-Type:', contentType);
        const responseText = await response.text();
        console.log('Raw response text (first 500 chars):', responseText.substring(0, 500));
        alert('Settings saved, but server response format was unexpected. Please verify changes.');
        return { message: 'Settings saved, but server response format was unexpected.' };
    }

  } catch (error) {
    console.error('Error in saveSettingsToServer function:', error.message);
    if (!error.message.toLowerCase().includes('authentication failed')) { // Avoid double alert
        alert(`Error saving settings: ${error.message}`);
    }
    return { error: `Failed to save settings: ${error.message}` };
  }
}

async function fetchCarouselImages() {
  try {
    const response = await fetch(`${API_BASE_URL}/api/carousel`); // Added /api prefix
    if (!response.ok) {
        const errorBody = await response.text().catch(() => "Could not read error body");
        console.error(`Error fetching carousel images: ${response.status} ${response.statusText}. Body: ${errorBody}`);
        throw new Error(`Network response was not ok (${response.status}).`);
    }
    const data = await response.json();
    return Array.isArray(data) ? data : [];
  } catch (error) {
    console.error('Error fetching carousel images:', error);
    return [];
  }
}

async function removeCarouselImageAdmin(id) {
  if (!id) { alert('Error: Image ID is missing.'); return; }
  if (!confirm('Are you sure you want to delete this carousel image?')) return;
  try {
    const response = await fetch(`${API_BASE_URL}/api/carousel/${id}`, { method: 'DELETE' }); // Added /api prefix
    if (!response.ok) {
        const responseText = await response.text();
        let errorData = { message: `Failed to remove image (${response.status}).`};
        try { errorData = JSON.parse(responseText); } catch (e) { console.warn("Non-JSON error response for carousel delete.");}
        throw new Error(errorData.message);
    }
    await response.json(); 
    alert('Carousel image removed successfully.');
    loadAdminData(); 
  } catch (error) {
    console.error('Error removing carousel image:', error);
    alert(`Error removing image: ${error.message}`);
  }
}

async function loadAdminData() {
  try {
    if (isAdminPage()) {
      await initializeEditors();
    }

    const settings = await fetchSettings();
    if (!settings) return; // Stop if fetchSettings handled a redirect

    const carouselImages = await fetchCarouselImages();
    applyBaseSettings(settings); 

    if (isAdminPage()) {
      getElement('schoolName').value = settings.schoolName || '';
      getElement('defaultHeroTitle').value = settings.defaultHeroTitle || '';
      getElement('school-tagline').value = settings.schoolTagline || '';
      getElement('defaultHeroTagline').value = settings.defaultHeroTagline || '';
      
      getElement('currentLogoURL').value = settings.logoURL || '';
      getElement('logoPreviewAdmin').src = settings.logoURL || '#';
      getElement('logoPreviewAdmin').style.display = settings.logoURL ? 'block' : 'none';
      getElement('defaultLogoURL').value = settings.defaultLogoURL || '';

      getElement('currentAboutImageURL').value = settings.aboutUsImageURL || '';
      getElement('aboutImagePreviewAdmin').src = settings.aboutUsImageURL || '#';
      getElement('aboutImagePreviewAdmin').style.display = settings.aboutUsImageURL ? 'block' : 'none';
      getElement('defaultAboutImageURL').value = settings.defaultAboutImageURL || '';

      getElement('currentAcademicsImageURL').value = settings.academicsImageURL || '';
      getElement('academicsImagePreviewAdmin').src = settings.academicsImageURL || '#';
      getElement('academicsImagePreviewAdmin').style.display = settings.academicsImageURL ? 'block' : 'none';
      getElement('defaultAcademicsImageURL').value = settings.defaultAcademicsImageURL || '';
      
      if (aboutUsTextEditorInstance) aboutUsTextEditorInstance.setData(settings.aboutUsText || '');
      if (academicsEditorInstance) academicsEditorInstance.setData(settings.academics || '');
      if (admissionEditorInstance) admissionEditorInstance.setData(settings.admission || '');
      if (facilitiesTextEditorInstance) facilitiesTextEditorInstance.setData(settings.facilitiesText || '');

      getElement('fontSelect').value = settings.schoolFont || "'Poppins', sans-serif";
      getElement('themeSelect').value = settings.schoolTheme || "light";

      getElement('socialWhatsapp').value = settings.socialWhatsapp || '';
      getElement('contactMapEmbedURL').value = settings.contactMapEmbedURL || '';
      const socialLinks = settings.socialLinks || {};
      getElement('socialFacebook').value = socialLinks.facebook || '';
      getElement('socialTwitter').value = socialLinks.twitter || '';
      getElement('socialInstagram').value = socialLinks.instagram || '';
      getElement('socialLinkedIn').value = socialLinks.linkedin || '';
      getElement('socialYouTube').value = socialLinks.youtube || '';

      generateFacilityCardInputsAdmin(settings.facilityCards || []);
      
      getElement('defaultCarouselImageURL').value = settings.defaultCarouselImageURL || '';
      getElement('defaultCarouselAltText').value = settings.defaultCarouselAltText || '';
      getElement('defaultCarouselLink').value = settings.defaultCarouselLink || '';

      const contactAction = settings.contactFormAction || 'whatsapp';
      const whatsappRadio = getElement('contactActionWhatsapp');
      const emailRadio = getElement('contactActionEmail');
      if (whatsappRadio && emailRadio) {
          if (contactAction === 'email') emailRadio.checked = true;
          else whatsappRadio.checked = true;
      }
      getElement('schoolContactEmail').value = settings.schoolContactEmail || '';
      getElement('adminSchoolWhatsappNumber').value = settings.adminSchoolWhatsappNumber || '';

      loadGradientSettings(settings);
      displayCarouselImagesAdmin(carouselImages);

    } else { 
      applyPublicSchoolDisplaySettings(settings);
      populateCarouselPublic(carouselImages, settings); 
      populateFacilityCardsPublic(settings.facilityCards || [], settings.facilitiesText);
      populateSocialLinksPublic(settings.socialLinks || {}, settings.socialWhatsapp);
      applyMapPublic(settings.contactMapEmbedURL);
    }

    const currentYear = new Date().getFullYear();
    querySelectorAll('[data-current-year]').forEach(el => el.textContent = currentYear);
    querySelectorAll('[data-next-year]').forEach(el => el.textContent = currentYear + 1);

  } catch (error) {
    console.error('Error during loadAdminData:', error.message);
    if (isAdminPage() && !error.message.toLowerCase().includes('session expired')) {
        alert('Failed to load some settings. Some fields might be empty or using defaults. Check console.');
    }
  }
}

function loadGradientSettings(settings) {
    const sections = ['hero', 'about', 'admissions', 'academics', 'facilities', 'contact'];
    sections.forEach(section => {
        const gradientData = settings[`${section}Gradient`] || {};
        if (getElement(`${section}GradientColor1`)) {
            getElement(`${section}GradientColor1`).value = gradientData.color1 || '#000000';
            getElement(`${section}GradientColor2`).value = gradientData.color2 || '#000000';
            getElement(`${section}GradientColor3`).value = gradientData.color3 || '#000000';
            getElement(`${section}GradientColor4`).value = gradientData.color4 || '#000000';
            getElement(`${section}GradientDirection`).value = gradientData.direction || 'to right';
        }
    });
}

async function handleImageUpload(inputId, previewId, currentUrlId, endpoint, formDataKey) {
    const uploadInput = getElement(inputId);
    let finalURL = getElement(currentUrlId).value; 

    if (uploadInput && uploadInput.files[0]) {
        const formData = new FormData();
        formData.append(formDataKey, uploadInput.files[0]);
        try {
            const response = await fetch(`${API_BASE_URL}/api/${endpoint}`, { method: 'POST', body: formData }); // Added /api prefix

            if (!response.ok) {
                const responseText = await response.text();
                let errorDetail = `Upload failed for ${formDataKey}. Server responded with ${response.status}.`;
                 if (response.status === 401 || response.status === 403) { // Handle auth error during upload
                    alert('Authentication error during upload. Please log in again.');
                    window.location.href = '/login.html?sessionExpired=true';
                    throw new Error('Upload auth failed.');
                }
                try { if (response.headers.get("content-type")?.includes("application/json")) { const errorJson = JSON.parse(responseText); errorDetail = errorJson.message || JSON.stringify(errorJson); } } catch (e) { /* ignore */ }
                throw new Error(errorDetail);
            }

            const result = await response.json(); 
            if (result.url) {
                finalURL = result.url;
                getElement(currentUrlId).value = finalURL;
                const preview = getElement(previewId);
                if (preview) { preview.src = finalURL; preview.style.display = 'block'; }
            } else { throw new Error(`URL not found in ${formDataKey} upload response.`); }
        } catch (error) {
            console.error(`Error during ${formDataKey} upload process:`, error);
            throw new Error(`Failed to upload ${formDataKey}: ${error.message}`);
        }
    }
    return finalURL;
}

async function saveAdminSettings() {
  if (!isAdminPage()) return;
  const saveButton = querySelector('.container > button.btn-primary');
  const originalButtonText = saveButton.innerHTML;
  saveButton.disabled = true;
  saveButton.innerHTML = 'Saving... <span class="spinner-border spinner-border-sm"></span>';


  let finalLogoURL = getElement('currentLogoURL')?.value || '';
  let finalAboutImageURL = getElement('currentAboutImageURL')?.value || '';
  let finalAcademicsImageURL = getElement('currentAcademicsImageURL')?.value || '';

  try {
    if (getElement('logoUpload')?.files[0]) {
      finalLogoURL = await handleImageUpload('logoUpload', 'logoPreviewAdmin', 'currentLogoURL', 'upload-logo', 'logo');
    }
    if (getElement('aboutImageUpload')?.files[0]) {
      finalAboutImageURL = await handleImageUpload('aboutImageUpload', 'aboutImagePreviewAdmin', 'currentAboutImageURL', 'upload-about-image', 'aboutImage');
    }
    if (getElement('academicsImageUpload')?.files[0]) {
      finalAcademicsImageURL = await handleImageUpload('academicsImageUpload', 'academicsImagePreviewAdmin', 'currentAcademicsImageURL', 'upload-academics-image', 'academicsImage');
    }
  } catch (uploadError) {
      console.error('An error occurred during one of the image uploads:', uploadError.message);
      if (!uploadError.message.includes('Upload auth failed.')) { // Avoid double alert
        alert(`Image Upload Error: ${uploadError.message}. Settings save aborted.`);
      }
      saveButton.disabled = false;
      saveButton.innerHTML = originalButtonText;
      return; 
  }

  const facilityCards = [];
  for (let i = 0; i < MAX_FACILITY_CARDS; i++) {
      const iconClass = getElement(`facilityIcon${i}`)?.value.trim() || '';
      const title = getElement(`facilityTitle${i}`)?.value.trim() || '';
      const description = getElement(`facilityDesc${i}`)?.value.trim() || '';
      facilityCards.push({ iconClass, title, description });
  }

  const settingsToSave = {
    schoolName: getElement('schoolName')?.value || '',
    defaultHeroTitle: getElement('defaultHeroTitle')?.value || '',
    schoolTagline: getElement('school-tagline')?.value || '',
    defaultHeroTagline: getElement('defaultHeroTagline')?.value || '',
    logoURL: finalLogoURL, defaultLogoURL: getElement('defaultLogoURL')?.value || '',
    aboutUsImageURL: finalAboutImageURL, defaultAboutImageURL: getElement('defaultAboutImageURL')?.value || '',
    academicsImageURL: finalAcademicsImageURL, defaultAcademicsImageURL: getElement('defaultAcademicsImageURL')?.value || '',
    schoolFont: getElement('fontSelect')?.value || "'Poppins', sans-serif",
    schoolTheme: getElement('themeSelect')?.value || "light",
    aboutUsText: aboutUsTextEditorInstance ? aboutUsTextEditorInstance.getData() : '',
    academics: academicsEditorInstance ? academicsEditorInstance.getData() : '',
    admission: admissionEditorInstance ? admissionEditorInstance.getData() : '',
    facilitiesText: facilitiesTextEditorInstance ? facilitiesTextEditorInstance.getData() : '',
    socialLinks: {
        facebook: getElement('socialFacebook')?.value.trim() || '', twitter: getElement('socialTwitter')?.value.trim() || '',
        instagram: getElement('socialInstagram')?.value.trim() || '', linkedin: getElement('socialLinkedIn')?.value.trim() || '',
        youtube: getElement('socialYouTube')?.value.trim() || '',
    },
    socialWhatsapp: getElement('socialWhatsapp')?.value.trim() || '',
    contactMapEmbedURL: getElement('contactMapEmbedURL')?.value.trim() || '',
    facilityCards: facilityCards,
    defaultCarouselImageURL: getElement('defaultCarouselImageURL')?.value.trim() || '',
    defaultCarouselAltText: getElement('defaultCarouselAltText')?.value.trim() || '',
    defaultCarouselLink: getElement('defaultCarouselLink')?.value.trim() || '',
    contactFormAction: querySelector('input[name="contactFormAction"]:checked')?.value || 'whatsapp',
    schoolContactEmail: getElement('schoolContactEmail')?.value.trim() || '',
    adminSchoolWhatsappNumber: getElement('adminSchoolWhatsappNumber')?.value.trim() || '',
  };
  
  const gradientSections = ['hero', 'about', 'admissions', 'academics', 'facilities', 'contact'];
  const currentSettings = await fetchSettings(); 
  if(!currentSettings) { // If fetchSettings led to a redirect
      saveButton.disabled = false;
      saveButton.innerHTML = originalButtonText;
      return;
  }


  gradientSections.forEach(section => {
      if (getElement(`${section}GradientColor1`)) {
        settingsToSave[`${section}Gradient`] = {
            color1: getElement(`${section}GradientColor1`)?.value, color2: getElement(`${section}GradientColor2`)?.value,
            color3: getElement(`${section}GradientColor3`)?.value, color4: getElement(`${section}GradientColor4`)?.value,
            direction: getElement(`${section}GradientDirection`)?.value || 'to right',
        };
      } else if (section === 'hero' && currentSettings.heroGradient) {
        settingsToSave.heroGradient = currentSettings.heroGradient; 
      } else if (section === 'hero') {
        settingsToSave.heroGradient = { color1: '#007bff', color2: '#6f42c1', color3: '#fd7e14', color4: '#00c6ff', direction: '45deg'};
      }
  });

  try {
    const result = await saveSettingsToServer(settingsToSave);
    if (result && !result.error) {
      alert('Settings saved successfully!');
      loadAdminData(); 
    }
  } catch (error) { 
    // Error already handled and alerted by saveSettingsToServer or handleImageUpload
    console.error('Error in saveAdminSettings (final save step):', error.message);
  } finally {
    saveButton.disabled = false;
    saveButton.innerHTML = originalButtonText;
  }
}

function displayCarouselImagesAdmin(images) {
    const container = getElement('carousel-images-container');
    if (!container) { console.error('Carousel admin container not found!'); return; }
    container.innerHTML = '';
    if (!images || images.length === 0) {
        container.innerHTML = '<p class="text-muted">No carousel images uploaded. Add one or set a default.</p>';
        return;
    }
    images.forEach(image => {
        if (!image || !image.image_url || !image.id) { console.warn('Skipping invalid image:', image); return; }
        const div = document.createElement('div');
        div.className = 'carousel-image-entry';
        const fileName = image.file_name || (image.image_url ? new URL(image.image_url, window.location.origin).pathname.split('/').pop() : 'N/A');
        div.innerHTML = `
            <div class="carousel-image-info">
                <img src="${image.image_url}" alt="${image.alt_text || 'Carousel'}" class="carousel-image-preview">
                <span>${image.alt_text || 'Unnamed'} (${fileName})</span>
                ${image.link_url ? `<span><br><small>Links to: ${image.link_url}</small></span>` : ''}
            </div>
            <button class="btn btn-sm btn-danger" onclick="removeCarouselImageAdmin('${image.id}')"><i class="bi bi-trash"></i></button>
        `;
        container.appendChild(div);
    });
}

async function uploadCarouselImage() {
    const fileInput = getElement('carousel-image-upload');
    const altInput = getElement('carousel-image-alt');
    const linkInput = getElement('carousel-image-link');

    if (!fileInput.files[0]) { alert('Please select an image file.'); return; }
    if (!altInput.value.trim()) { alert('Please provide Alt Text / Caption.'); return; }

    const formData = new FormData();
    formData.append('carouselImage', fileInput.files[0]); 
    formData.append('altText', altInput.value.trim()); 
    formData.append('linkURL', linkInput.value.trim());

    try {
        const response = await fetch(`${API_BASE_URL}/api/carousel`, { method: 'POST', body: formData }); // Added /api prefix
        if (!response.ok) {
            const responseText = await response.text();
            let errorData = { message: `Upload failed (${response.status}).`};
            if (response.status === 401 || response.status === 403) { // Handle auth error during upload
                alert('Authentication error during upload. Please log in again.');
                window.location.href = '/login.html?sessionExpired=true';
                throw new Error('Upload auth failed.');
            }
            try { errorData = JSON.parse(responseText); } catch (e) { /* ignore */ }
            throw new Error(errorData.message);
        }
        await response.json();
        alert('Carousel image uploaded successfully!');
        fileInput.value = ''; altInput.value = ''; linkInput.value = '';
        loadAdminData();
    } catch (error) {
        console.error('Error uploading carousel image:', error.message);
         if (!error.message.includes('Upload auth failed.')) {
            alert(`Error uploading carousel image: ${error.message}`);
        }
    }
}

function applyBaseSettings(settings) {
    document.documentElement.setAttribute('data-theme', settings.schoolTheme || 'light');
    document.documentElement.style.setProperty('--dynamic-body-font', settings.schoolFont || "'Poppins', sans-serif");
}

function applyPublicSchoolDisplaySettings(settings) {
    const finalSchoolName = settings.schoolName || settings.defaultHeroTitle || 'Our School';
    const finalTagline = settings.schoolTagline || settings.defaultHeroTagline || 'Nurturing Young Minds';
    
    getElement('pageTitle').textContent = `${finalSchoolName} | ${finalTagline.substring(0, 50)}`;
    getElement('metaDescription').content = `Welcome to ${finalSchoolName}. ${finalTagline}. Discover our programs.`;

    querySelectorAll('.school-name').forEach(el => el.textContent = finalSchoolName);
    getElement('heroSchoolName').textContent = finalSchoolName; 
    getElement('navSchoolNameDisplay').textContent = finalSchoolName;
    getElement('aboutSchoolName').textContent = finalSchoolName;
    getElement('footerSchoolNameDisplay').textContent = finalSchoolName;
    getElement('footerCopyrightSchoolName').textContent = finalSchoolName;

    const logoUrlToUse = settings.logoURL || settings.defaultLogoURL;
    getElement('logoURL').src = logoUrlToUse; getElement('logoURL').alt = `${finalSchoolName} Logo`;
    getElement('footerLogoURL').src = logoUrlToUse; getElement('footerLogoURL').alt = `${finalSchoolName} Logo`;

    getElement('aboutUsImage').src = settings.aboutUsImageURL || settings.defaultAboutImageURL;
    getElement('aboutUsImage').alt = `About ${finalSchoolName}`;
    
    const academicsImageEl = getElement('academicsImage'); // This element was commented out in school.html
    if(academicsImageEl) {
      academicsImageEl.src = settings.academicsImageURL || settings.defaultAcademicsImageURL;
      academicsImageEl.alt = `Academics at ${finalSchoolName}`;
    }

    querySelector('.about-us-info').innerHTML = settings.aboutUsText || '<p>Info coming soon.</p>';
    querySelector('.admission-info').innerHTML = settings.admission || '<p>Details coming soon.</p>';
    querySelector('.academics-info-container .academics-dynamic-content').innerHTML = settings.academics || '<p>Curriculum details soon.</p>';
    querySelector('.facilities-overview-text').innerHTML = settings.facilitiesText || '<p>Excellent facilities offered.</p>';
    getElement('heroSchoolTagline').textContent = finalTagline;

    applySectionGradient('hero', settings.heroGradient || {});
    applySectionGradient('about', settings.aboutGradient || {});
    applySectionGradient('admissions', settings.admissionsGradient || {});
    applySectionGradient('academics', settings.academicsGradient || {});
    applySectionGradient('facilities', settings.facilitiesGradient || {});
    applySectionGradient('contact', settings.contactGradient || {});
}

function populateFacilityCardsPublic(facilityCardsData = [], facilitiesOverviewTextIfEmpty) {
    const container = getElement('facilityCardsPublicContainer');
    if (!container) return;
    container.innerHTML = ''; 
    const activeCards = facilityCardsData.filter(card => card.title || card.description || card.iconClass);
    if (activeCards.length === 0) {
        container.innerHTML = `<div class="col-12"><p class="text-center text-muted">${facilitiesOverviewTextIfEmpty || 'Facilities details soon.'}</p></div>`;
        return;
    }
    activeCards.slice(0, MAX_FACILITY_CARDS).forEach(card => {
        container.innerHTML += `
            <div class="col-md-6 col-lg-4 reveal">
              <div class="card facility-card h-100">
                <div class="card-body text-center">
                  <i class="bi ${card.iconClass || 'bi-check-circle-fill'} display-4 text-primary mb-3"></i>
                  <h5 class="card-title">${card.title || 'Facility'}</h5>
                  <p class="card-text">${card.description || 'Details.'}</p>
                </div>
              </div>
            </div>`;
    });
}

function populateSocialLinksPublic(socialLinks = {}, whatsappNumber) {
    const linkMapping = {
        'socialFacebookLink': socialLinks.facebook, 'socialTwitterLink': socialLinks.twitter,
        'socialInstagramLink': socialLinks.instagram, 'socialLinkedInLink': socialLinks.linkedin,
        'socialYouTubeLink': socialLinks.youtube,
    };
    for (const [elementId, url] of Object.entries(linkMapping)) {
        const linkElement = getElement(elementId);
        if (linkElement) {
            if (url && url.trim() !== '') {
                linkElement.href = url; linkElement.parentElement.style.display = 'inline-block';
            } else { linkElement.parentElement.style.display = 'none'; }
        }
    }
    const whatsappLinkEl = getElement('whatsappLink');
    if (whatsappLinkEl) {
        if (whatsappNumber && whatsappNumber.trim() !== '') {
            const sanitizedNumber = whatsappNumber.replace(/\D/g, '');
            whatsappLinkEl.href = `https://wa.me/${sanitizedNumber}`; whatsappLinkEl.style.display = 'flex';
        } else { whatsappLinkEl.style.display = 'none'; }
    }
}

function applyMapPublic(mapEmbedURL) {
    const mapContainer = getElement('mapContainer');
    const schoolMapIframe = getElement('schoolMap');
    const mapPlaceholder = getElement('mapPlaceholder');
    if (schoolMapIframe && mapContainer && mapPlaceholder) {
        if (mapEmbedURL && mapEmbedURL.trim() !== '') {
            schoolMapIframe.src = mapEmbedURL; mapContainer.style.display = 'flex'; mapPlaceholder.style.display = 'none';
        } else { mapContainer.style.display = 'none'; mapPlaceholder.style.display = 'block'; }
    }
}

function applySectionGradient(sectionId, gradientSettings) {
    const sectionElement = document.getElementById(sectionId);
    if (!sectionElement || !gradientSettings) { if (sectionElement) sectionElement.style.backgroundImage = ''; return; }
    const colors = [gradientSettings.color1, gradientSettings.color2, gradientSettings.color3, gradientSettings.color4]
        .filter(color => color && color.trim() !== '' && color.toLowerCase() !== '#000000' && color.toLowerCase() !== '#000');
    if (colors.length === 0) { sectionElement.style.backgroundImage = ''; sectionElement.style.backgroundColor = ''; return; }
    if (colors.length === 1) { sectionElement.style.backgroundImage = ''; sectionElement.style.backgroundColor = colors[0]; return; }
    const direction = gradientSettings.direction || 'to right';
    sectionElement.style.backgroundColor = ''; sectionElement.style.backgroundImage = `linear-gradient(${direction}, ${colors.join(', ')})`;
}

function isAdminPage() { return window.location.pathname.includes('/admin.html'); }

function populateCarouselPublic(images, settings) {
    const carouselInner = getElement('carousel-inner');
    const carouselIndicators = getElement('carousel-indicators');
    if (!carouselInner || !carouselIndicators) return;
    carouselInner.innerHTML = ''; carouselIndicators.innerHTML = '';

    if (!images || images.length === 0) {
        const defaultImageURL = settings.defaultCarouselImageURL || '/uploads/placeholder-carousel.jpg';
        const defaultAltText = settings.defaultCarouselAltText || 'Campus Highlight';
        const defaultLink = settings.defaultCarouselLink || '#';
        const itemDiv = document.createElement('div'); itemDiv.className = 'carousel-item active';
        let imgHtml = `<img src="${defaultImageURL}" class="d-block w-100" alt="${defaultAltText}">`;
        if (defaultLink && defaultLink !== '#' && defaultLink.trim() !== '') {
            const targetLink = defaultLink.startsWith('http') ? defaultLink : (defaultLink.startsWith('#') ? defaultLink : '#' + defaultLink);
            imgHtml = `<a href="${targetLink}">${imgHtml}</a>`;
        }
        itemDiv.innerHTML = imgHtml; carouselInner.appendChild(itemDiv);
        return;
    }
    images.forEach((image, index) => {
        const itemDiv = document.createElement('div'); itemDiv.className = `carousel-item${index === 0 ? ' active' : ''}`;
        let imgHtml = `<img src="${image.image_url}" class="d-block w-100" alt="${image.alt_text || 'School image'}">`;
        if (image.link_url && image.link_url.trim() !== '' && image.link_url.trim() !== '#') {
            const targetLink = image.link_url.startsWith('http') ? image.link_url : (image.link_url.startsWith('#') ? image.link_url : '#' + image.link_url);
            imgHtml = `<a href="${targetLink}" ${image.link_url.startsWith('http') ? 'target="_blank" rel="noopener noreferrer"' : ''}>${imgHtml}</a>`;
        }
        itemDiv.innerHTML = imgHtml; carouselInner.appendChild(itemDiv);
        const indicatorButton = document.createElement('button'); indicatorButton.type = 'button';
        indicatorButton.dataset.bsTarget = '#schoolCarousel'; indicatorButton.dataset.bsSlideTo = index.toString();
        if (index === 0) { indicatorButton.className = 'active'; indicatorButton.setAttribute('aria-current', 'true'); }
        indicatorButton.setAttribute('aria-label', `Slide ${index + 1}`); carouselIndicators.appendChild(indicatorButton);
    });
}

async function logoutAdmin() {
    if (confirm('Are you sure you want to logout?')) {
        try {
            const response = await fetch(`${API_BASE_URL}/api/logout`, { method: 'POST' }); // Added /api prefix
            const data = await response.json().catch(() => ({ message: "Logout action completed." }));
            if (response.ok) {
                alert(data.message || 'Logout successful.');
                window.location.href = '/login.html';
            } else {
                alert(`Logout failed: ${data.message || `Server responded with ${response.status}`}`);
                window.location.href = '/login.html'; // Still redirect
            }
        } catch (error) {
            console.error('Error during logout fetch:', error);
            alert('A network error occurred during logout. Redirecting to login.');
            window.location.href = '/login.html';
        }
    }
}

function setupImagePreviews() {
    const imageInputs = [
        { inputId: 'logoUpload', previewId: 'logoPreviewAdmin', currentUrlId: 'currentLogoURL' },
        { inputId: 'aboutImageUpload', previewId: 'aboutImagePreviewAdmin', currentUrlId: 'currentAboutImageURL' },
        { inputId: 'academicsImageUpload', previewId: 'academicsImagePreviewAdmin', currentUrlId: 'currentAcademicsImageURL' }
    ];
    imageInputs.forEach(item => {
        const inputElement = getElement(item.inputId);
        const previewElement = getElement(item.previewId);
        if (inputElement && previewElement) {
            inputElement.addEventListener('change', function() {
                if (this.files && this.files[0]) {
                    const reader = new FileReader();
                    reader.onload = (e) => { previewElement.src = e.target.result; previewElement.style.display = 'block'; }
                    reader.readAsDataURL(this.files[0]);
                } else {
                    const currentUrlField = getElement(item.currentUrlId);
                    if (currentUrlField && currentUrlField.value) {
                         previewElement.src = currentUrlField.value; previewElement.style.display = 'block';
                    } else { previewElement.src = '#'; previewElement.style.display = 'none'; }
                }
            });
        }
    });
}

// Global assignments for HTML onclick handlers
window.saveAdminSettings = saveAdminSettings;
window.uploadCarouselImage = uploadCarouselImage;
window.removeCarouselImageAdmin = removeCarouselImageAdmin;
window.logoutAdmin = logoutAdmin;

document.addEventListener('DOMContentLoaded', () => {
    loadAdminData(); // This will also initialize editors if it's the admin page
    if (isAdminPage()) {
        setupImagePreviews(); 
    }
});