// --- Section Navigation ---
function showSection(sectionId) {
  // Hide all sections
  document.querySelectorAll('.admin-section').forEach(sec => sec.classList.remove('active'));
  // Show the selected section
  document.getElementById(sectionId).classList.add('active');
  // Update navbar active state
  document.querySelectorAll('.nav-link').forEach(link => link.classList.remove('active'));
  document.querySelectorAll('.nav-link').forEach(link => {
    if (link.getAttribute('onclick') && link.getAttribute('onclick').includes(sectionId)) {
      link.classList.add('active');
    }
  });
}

// Refresh Data Functionality
function refreshData() {
  const alertBox = document.getElementById('customAlert');
  if (alertBox) {
    alertBox.style.display = 'block';
    alertBox.querySelector('p').textContent = 'Refreshing data...';
  }
  setTimeout(() => {
    if (alertBox) alertBox.style.display = 'none';
  }, 1200);
}

// --- Profile Tabs ---
function switchProfileTab(tab) {
  document.querySelectorAll('.profile-tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.profile-section').forEach(s => s.classList.remove('active'));
  document.querySelector(`.profile-tab[onclick*="${tab}"]`).classList.add('active');
  document.getElementById(tab + 'Section').classList.add('active');
}

// --- User Profile View ---
function viewUserProfile(userId) {
  // Example: You'd fetch user data from backend here
  let user = {
    1: {
      name: "John Doe",
      email: "john@example.com",
      avatar: "https://ui-avatars.com/api/?name=John+Doe&background=random",
      role: "Administrator",
      status: "Active",
      department: "IT Department",
      phone: "+1 555-1234",
      joinDate: "2022-01-15",
      lastLogin: "2024-03-20 14:30"
    },
    2: {
      name: "Jane Smith",
      email: "jane@example.com",
      avatar: "https://ui-avatars.com/api/?name=Jane+Smith&background=random",
      role: "Standard User",
      status: "Active",
      department: "Marketing",
      phone: "+1 555-5678",
      joinDate: "2023-06-10",
      lastLogin: "2024-03-19 09:15"
    }
  }[userId];

  if (!user) return;

  document.getElementById('profileAvatar').src = user.avatar;
  document.getElementById('profileName').textContent = user.name;
  document.getElementById('profileEmail').textContent = user.email;
  document.getElementById('profileRole').textContent = user.role;
  document.getElementById('profileRole').className = 'role-badge ' + (user.role === 'Administrator' ? 'admin' : 'standard');
  document.getElementById('profileStatus').textContent = user.status;
  document.getElementById('profileStatus').className = 'status-badge ' + (user.status === 'Active' ? 'active' : 'inactive');
  document.getElementById('profileDepartment').textContent = user.department;
  document.getElementById('profilePhone').textContent = user.phone;
  document.getElementById('profileJoinDate').textContent = user.joinDate;
  document.getElementById('profileLastLogin').textContent = user.lastLogin;

  document.getElementById('usersTableView').style.display = 'none';
  document.getElementById('userProfileView').style.display = 'flex';
  // Reset to overview tab
  switchProfileTab('overview');
}

function showUsersTable() {
  document.getElementById('userProfileView').style.display = 'none';
  document.getElementById('usersTableView').style.display = 'block';
}

// --- Messages Section: Read Contact Messages ---
const contactMessages = [
  {
    id: 1,
    subject: "Account Verification Support",
    sender: "user@example.com",
    date: "2025-05-21 14:30",
    content: "Hello, I need assistance with my account verification process. The system is showing an error. Please help me resolve this as soon as possible. Thank you!"
  },
  {
    id: 2,
    subject: "Technical Support Required",
    sender: "support@example.com",
    date: "2025-05-20 09:15",
    content: "The facial recognition system is experiencing delays in processing large group scans. Can you please look into this issue?"
  }
];

function loadMessages() {
  const grid = document.querySelector('.messages-grid');
  grid.innerHTML = '';
  contactMessages.forEach(msg => {
    const card = document.createElement('div');
    card.className = 'message-card unread';
    card.dataset.messageId = msg.id;
    card.innerHTML = `
      <div class="message-status">
        <i class="fas fa-envelope"></i>
      </div>
      <div class="message-content">
        <div class="message-header">
          <h4>${msg.subject}</h4>
          <span class="message-date">
            <i class="far fa-calendar"></i> ${msg.date.split(' ')[0]}
            <i class="far fa-clock"></i> ${msg.date.split(' ')[1]}
          </span>
        </div>
        <div class="message-sender">
          <img src="logo.png" alt="User" class="sender-avatar">
          <span>${msg.sender}</span>
        </div>
        <div class="message-preview">
          ${msg.content.substring(0, 60)}...
        </div>
      </div>
      <div class="message-actions">
        <button class="action-btn view" title="View Message" onclick="viewMessage(${msg.id})">
          <i class="fas fa-eye"></i>
        </button>
        <button class="action-btn delete" title="Delete" onclick="deleteMessage(${msg.id})">
          <i class="fas fa-trash"></i>
        </button>
      </div>
    `;
    grid.appendChild(card);
  });
}

function viewMessage(messageId) {
  const msg = contactMessages.find(m => m.id == messageId);
  if (!msg) return;
  let modal = document.getElementById('viewMessageModal');
  if (!modal) {
    modal = document.createElement('div');
    modal.className = 'modal';
    modal.id = 'viewMessageModal';
    modal.innerHTML = `
      <div class="modal-content" style="max-width:500px;">
        <div class="modal-header">
          <h3><i class="fas fa-envelope-open"></i> Message Details</h3>
          <button class="close-modal" onclick="closeModal('viewMessageModal')">
            <i class="fas fa-times"></i>
          </button>
        </div>
        <div class="modal-body" id="viewMessageBody"></div>
      </div>
    `;
    document.body.appendChild(modal);
  }
  document.getElementById('viewMessageBody').innerHTML = `
    <strong>Subject:</strong> ${msg.subject}<br>
    <strong>From:</strong> ${msg.sender}<br>
    <strong>Date:</strong> ${msg.date}<br>
    <hr>
    <div style="white-space: pre-line; font-size: 1.05rem;">${msg.content}</div>
  `;
  modal.style.display = 'block';
}

function deleteMessage(messageId) {
  if(confirm('Are you sure you want to delete this message?')) {
    const idx = contactMessages.findIndex(m => m.id == messageId);
    if (idx !== -1) contactMessages.splice(idx, 1);
    loadMessages();
    alert('Message deleted successfully!');
    closeModal('viewMessageModal');
  }
}

function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) modal.style.display = 'none';
}

// Change Profile Photo
function changeProfilePhoto() {
  alert('Change Profile Photo functionality coming soon!');
  // You can implement a file input and upload logic here
}

// Edit User
function editUserProfile() {
  alert('Edit User functionality coming soon!');
  // You can open a modal or form to edit user details
}

// Navigate to the "Messages" section
function showSection(sectionId) {
  // Hide all sections
  document.querySelectorAll('.admin-section').forEach(sec => sec.classList.remove('active'));
  // Show the selected section
  document.getElementById(sectionId).classList.add('active');
  // Update navbar active state
  document.querySelectorAll('.nav-link').forEach(link => link.classList.remove('active'));
  document.querySelectorAll('.nav-link').forEach(link => {
    if (link.getAttribute('onclick') && link.getAttribute('onclick').includes(sectionId)) {
      link.classList.add('active');
    }
  });
}

// Sample Users Data
const users = [
  { id: 1, name: "John Doe", email: "john@example.com", role: "Admin", status: "Active" },
  { id: 2, name: "Jane Smith", email: "jane@example.com", role: "User", status: "Inactive" },
];

// Display Users in the Table
function displayUsers() {
  const tableBody = document.getElementById("usersTableBody");
  if (!tableBody) {
    console.error("Error: Element with ID 'usersTableBody' not found in the DOM.");
    return; // Exit the function if the element is not found
  }

  tableBody.innerHTML = ""; // Clear existing rows
  users.forEach(user => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${user.id}</td>
      <td>${user.name}</td>
      <td>${user.email}</td>
      <td>${user.role}</td>
      <td>${user.status}</td>
      <td>
        <div class="actions-btn">
          <button onclick="editUser(${user.id})">Edit</button>
          <button onclick="deleteUser(${user.id})">Delete</button>
        </div>
      </td>
    `;
    tableBody.appendChild(row);
  });
}

// Add New User
function addUser(event) {
  event.preventDefault();
  const name = document.getElementById("userName").value;
  const email = document.getElementById("userEmail").value;
  const role = document.getElementById("userRole").value;
  const id = users.length + 1;
  users.push({ id, name, email, role, status: "Active" });
  displayUsers();
  closeModal("addUserModal");
}

// Edit User (Placeholder)
function editUser(id) {
  const user = users.find(user => user.id === id);
  if (!user) return;

  // Open the modal and pre-fill the form
  document.getElementById("addUserModal").style.display = "flex";
  document.getElementById("userName").value = user.name;
  document.getElementById("userEmail").value = user.email;
  document.getElementById("userRole").value = user.role;

  // Update the form submission to edit the user
  const form = document.getElementById("addUserForm");
  form.onsubmit = function (event) {
    event.preventDefault();
    user.name = document.getElementById("userName").value;
    user.email = document.getElementById("userEmail").value;
    user.role = document.getElementById("userRole").value;
    displayUsers();
    closeModal("addUserModal");
    form.onsubmit = addUser; // Reset the form submission to add new users
  };
}

// Delete User
function deleteUser(id) {
  const index = users.findIndex(user => user.id === id);
  if (index !== -1) {
    users.splice(index, 1);
    displayUsers();
  }
}

// Filter Users
function filterUsers() {
  const searchValue = document.getElementById("userSearch").value.toLowerCase();
  const filteredUsers = users.filter(user =>
    user.name.toLowerCase().includes(searchValue) ||
    user.email.toLowerCase().includes(searchValue) ||
    user.role.toLowerCase().includes(searchValue)
  );

  const tableBody = document.getElementById("usersTableBody");
  tableBody.innerHTML = ""; // Clear existing rows

  filteredUsers.forEach(user => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${user.id}</td>
      <td>${user.name}</td>
      <td>${user.email}</td>
      <td>${user.role}</td>
      <td>${user.status}</td>
      <td>
        <div class="actions-btn">
          <button onclick="editUser(${user.id})"><i class="fas fa-edit"></i></button>
          <button onclick="deleteUser(${user.id})"><i class="fas fa-trash"></i></button>
        </div>
      </td>
    `;
    tableBody.appendChild(row);
  });
}

// Open Modal
function openAddUserModal() {
  document.getElementById("addUserModal").style.display = "flex";
}

// Close Modal
function closeModal(modalId) {
  document.getElementById(modalId).style.display = "none";
}

// Initialize Users Table
document.addEventListener("DOMContentLoaded", displayUsers);

// Attach Refresh Button Event
document.addEventListener('DOMContentLoaded', function() {
  document.querySelectorAll('.refresh-btn').forEach(btn => {
    btn.onclick = refreshData;
  });
});

// --- Chart.js Integration ---
const ctx = document.getElementById('performanceChart');
if (ctx) {
  const performanceChart = new Chart(ctx.getContext('2d'), {
    type: 'line',
    data: {
      labels: ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'],
      datasets: [{
        label: 'Performance',
        data: [65, 59, 80, 81, 56, 55, 40],
        borderColor: '#4a90e2',
        backgroundColor: 'rgba(74, 144, 226, 0.2)',
        fill: true,
        tension: 0.4
      }]
    },
    options: {
      responsive: true,
      plugins: {
        legend: {
          display: false
        }
      }
    }
  });
}

function handleSubmit(event) {
  event.preventDefault();

  // Get form data
  const name = document.getElementById("name").value;
  const email = document.getElementById("email").value;
  const phone = document.getElementById("phone").value || "N/A";
  const inquiry = document.getElementById("inquiry").value;
  const message = document.getElementById("message").value;

  // Create a message object
  const newMessage = {
    id: Date.now(),
    name,
    email,
    phone,
    inquiry,
    message,
  };

  // Save the message to localStorage
  const messages = JSON.parse(localStorage.getItem("messages")) || [];
  messages.push(newMessage);
  localStorage.setItem("messages", JSON.stringify(messages));

  // Show success alert and reset the form
  alert("Thank you for your message. We will get back to you soon!");
  event.target.reset();
}

// Display Messages in the Messages Section
function displayMessages() {
  const messages = JSON.parse(localStorage.getItem("messages")) || [];
  const tableBody = document.getElementById("messagesTableBody");
  tableBody.innerHTML = ""; // Clear existing rows

  messages.forEach((message, index) => {
    const row = document.createElement("tr");
    row.innerHTML = `
      <td>${index + 1}</td>
      <td>${message.name}</td>
      <td>${message.email}</td>
      <td>${message.phone}</td>
      <td>${message.inquiry}</td>
      <td>${message.message}</td>
      <td>
        <div class="actions-btn">
          <button onclick="replyToMessage('${message.email}')"><i class="fas fa-reply"></i> Reply</button>
          <button onclick="markAsRead(${message.id})"><i class="fas fa-check"></i> Mark as Read</button>
          <button onclick="deleteMessage(${message.id})"><i class="fas fa-trash"></i> Delete</button>
        </div>
      </td>
    `;
    tableBody.appendChild(row);
  });
}

// Reply to a Message
function replyToMessage(email) {
  const subject = prompt("Enter the subject for your reply:");
  const body = prompt("Enter your reply message:");
  if (subject && body) {
    alert(`Reply sent to ${email}:\n\nSubject: ${subject}\nMessage: ${body}`);
    // You can integrate an email API here to send the reply
  }
}

// Mark a Message as Read
function markAsRead(id) {
  const messages = JSON.parse(localStorage.getItem("messages")) || [];
  const message = messages.find(msg => msg.id === id);
  if (message) {
    message.read = true; // Mark the message as read
    localStorage.setItem("messages", JSON.stringify(messages));
    alert("Message marked as read.");
    displayMessages();
  }
}

// Delete a Message
function deleteMessage(id) {
  if (confirm("Are you sure you want to delete this message?")) {
    let messages = JSON.parse(localStorage.getItem("messages")) || [];
    messages = messages.filter(message => message.id !== id);
    localStorage.setItem("messages", JSON.stringify(messages));
    alert("Message deleted successfully!");
    displayMessages();
  }
}

// Initialize Messages Table
document.addEventListener("DOMContentLoaded", displayMessages);

// Login as Admin
function loginAsAdmin() {
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;

  // Example admin credentials (replace with your actual logic)
  const adminEmail = "admin@example.com";
  const adminPassword = "admin123";

  if (email === adminEmail && password === adminPassword) {
    alert("Admin login successful!");
    window.location.href = "admin.html"; // Redirect to Admin page
  } else {
    alert("Invalid Admin credentials. Please try again.");
  }
}

function loginAsUser() {
  const email = document.getElementById("email").value;
  const password = document.getElementById("password").value;

  // Example user credentials (replace with your actual logic)
  const userEmail = "user@example.com";
  const userPassword = "user123";

  if (email === userEmail && password === userPassword) {
    alert("User login successful!");
    window.location.href = "dashboard.html"; // Redirect to User Dashboard
  } else {
    alert("Invalid User credentials. Please try again.");
  }
}

// Set animation delays for input groups
document.addEventListener("DOMContentLoaded", function () {
  const inputs = document.querySelectorAll(".input-group");
  inputs.forEach((input, index) => {
    input.style.setProperty("--input-index", index);
  });
});

async function analyzeCrowd() {
  const container = document.getElementById('crowdPlaceholder');
  const input = container.querySelector('input');
  const file = input.files[0];

  if (file) {
    try {
      // Hide upload button and show analyzing text
      const uploadBtn = container.querySelector('.upload-btn');
      const uploadText = container.querySelector('p');
      uploadBtn.style.display = 'none';
      uploadText.textContent = 'Analyzing...';

      // Simulate analysis delay
      await new Promise(resolve => setTimeout(resolve, 2000));

      // Show preview after analysis
      const previewContainer = container.querySelector('.preview-container');
      const imageData = await previewImage(file, previewContainer);
      previewContainer.style.display = 'block';

      // Hide the upload section and show the result container
      document.getElementById('crowdPlaceholder').style.display = 'none';
      document.getElementById('crowdResult').style.display = 'block';
      document.getElementById('uploadedCrowdImage').src = imageData;

      // Update the report generation date and time
      updateReportDateTime('crowdReportDateTime');
    } catch (error) {
      showError(container, 'Failed to analyze image. Please try again.');

      // Reset upload button and text on error
      const uploadBtn = container.querySelector('.upload-btn');
      const uploadText = container.querySelector('p');
      uploadBtn.style.display = 'inline-flex';
      uploadText.textContent = 'Upload an image of a crowd to analyze mask compliance and headcount';
    }
  }
}

async function analyzeFace() {
  const container = document.getElementById('facePlaceholder');
  const input = container.querySelector('input');
  const file = input.files[0];

  if (file) {
    try {
      // Hide upload button and show analyzing text
      const uploadBtn = container.querySelector('.upload-btn');
      const uploadText = container.querySelector('p');
      uploadBtn.style.display = 'none';
      uploadText.textContent = 'Analyzing...';

      // Simulate analysis delay
      await new Promise(resolve => setTimeout(resolve, 2000));

      // Show preview after analysis
      const previewContainer = container.querySelector('.preview-container');
      const imageData = await previewImage(file, previewContainer);
      previewContainer.style.display = 'block';

      // Hide the upload section and show the result container
      document.getElementById('facePlaceholder').style.display = 'none';
      document.getElementById('faceResult').style.display = 'block';
      document.getElementById('uploadedFaceImage').src = imageData;

      // Update the report generation date and time
      updateReportDateTime('faceReportDateTime');
    } catch (error) {
      showError(container, 'Failed to analyze image. Please try again.');

      // Reset upload button and text on error
      const uploadBtn = container.querySelector('.upload-btn');
      const uploadText = container.querySelector('p');
      uploadBtn.style.display = 'inline-flex';
      uploadText.textContent = 'Upload a face image to detect personal attributes';
    }
  }
}
 window.jsPDF = window.jspdf.jsPDF;

    // Add drag and drop support
    function initDragAndDrop() {
      const uploadSections = document.querySelectorAll('.upload-section');
      
      uploadSections.forEach(section => {
        section.addEventListener('dragover', (e) => {
          e.preventDefault();
          section.classList.add('drag-over');
        });

        section.addEventListener('dragleave', () => {
          section.classList.remove('drag-over');
        });

        section.addEventListener('drop', (e) => {
          e.preventDefault();
          section.classList.remove('drag-over');
          const file = e.dataTransfer.files[0];
          if (file && file.type.startsWith('image/')) {
            const input = section.querySelector('input[type="file"]');
            input.files = e.dataTransfer.files;
            input.dispatchEvent(new Event('change'));
          } else {
            showError(section, 'Please upload an image file.');
          }
        });
      });
    }

    function showError(container, message) {
      let errorDiv = container.querySelector('.error-message');
      if (!errorDiv) {
        errorDiv = document.createElement('div');
        errorDiv.className = 'error-message';
        container.appendChild(errorDiv);
      }
      errorDiv.textContent = message;
      errorDiv.style.display = 'block';
      setTimeout(() => {
        errorDiv.style.display = 'none';
      }, 5000);
    }

    function previewImage(file, previewContainer) {
      return new Promise((resolve, reject) => {
        const reader = new FileReader();
        reader.onload = (e) => {
          const img = previewContainer.querySelector('img');
          img.src = e.target.result;
          previewContainer.style.display = 'block';
          resolve(e.target.result);
        };
        reader.onerror = reject;
        reader.readAsDataURL(file);
      });
    }

    async function analyzeFace() {
      const container = document.getElementById('facePlaceholder');
      const input = container.querySelector('input');
      const file = input.files[0];

      if (file) {
        try {
          // Hide upload button and show analyzing text
          const uploadBtn = container.querySelector('.upload-btn');
          const uploadText = container.querySelector('p');
          uploadBtn.style.display = 'none';
          uploadText.textContent = 'Analyzing...';

          // Simulate analysis delay
          await new Promise(resolve => setTimeout(resolve, 2000));

          // Show preview after analysis
          const previewContainer = container.querySelector('.preview-container');
          const imageData = await previewImage(file, previewContainer);
          previewContainer.style.display = 'block';

          // Hide the upload section and show the result container
          document.getElementById('facePlaceholder').style.display = 'none';
          document.getElementById('faceResult').style.display = 'block';
          document.getElementById('uploadedFaceImage').src = imageData;

          // Update the report generation date and time
          updateReportDateTime('faceReportDateTime');
        } catch (error) {
          showError(container, 'Failed to analyze image. Please try again.');

          // Reset upload button and text on error
          const uploadBtn = container.querySelector('.upload-btn');
          const uploadText = container.querySelector('p');
          uploadBtn.style.display = 'inline-flex';
          uploadText.textContent = 'Upload a face image to detect personal attributes';
        }
      }
    }

    async function analyzeCrowd() {
      const container = document.getElementById('crowdPlaceholder');
      const input = container.querySelector('input');
      const file = input.files[0];

      if (file) {
        try {
          // Hide upload button and show analyzing text
          const uploadBtn = container.querySelector('.upload-btn');
          const uploadText = container.querySelector('p');
          uploadBtn.style.display = 'none';
          uploadText.textContent = 'Analyzing...';

          // Simulate analysis delay
          await new Promise(resolve => setTimeout(resolve, 2000));

          // Show preview after analysis
          const previewContainer = container.querySelector('.preview-container');
          const imageData = await previewImage(file, previewContainer);
          previewContainer.style.display = 'block';

          // Hide the upload section and show the result container
          document.getElementById('crowdPlaceholder').style.display = 'none';
          document.getElementById('crowdResult').style.display = 'block';
          document.getElementById('uploadedCrowdImage').src = imageData;

          // Update the report generation date and time
          updateReportDateTime('crowdReportDateTime');
        } catch (error) {
          showError(container, 'Failed to analyze image. Please try again.');

          // Reset upload button and text on error
          const uploadBtn = container.querySelector('.upload-btn');
          const uploadText = container.querySelector('p');
          uploadBtn.style.display = 'inline-flex';
          uploadText.textContent = 'Upload an image of a crowd to analyze mask compliance and headcount';
        }
      }
    }

    async function compressImage(dataUrl, maxWidth = 1200) {
      return new Promise((resolve) => {
        const img = new Image();
        img.onload = () => {
          const canvas = document.createElement('canvas');
          let width = img.width;
          let height = img.height;
          
          if (width > maxWidth) {
            height = (height * maxWidth) / width;
            width = maxWidth;
          }
          
          canvas.width = width;
          canvas.height = height;
          const ctx = canvas.getContext('2d');
          ctx.drawImage(img, 0, 0, width, height);
          resolve(canvas.toDataURL('image/jpeg', 0.8));
        };
        img.src = dataUrl;
      });
    }

    async function downloadFaceAnalysisPDF() {
      try {
        const element = document.getElementById('faceReport');
        
        // Create a clone of the element for PDF generation
        const clone = element.cloneNode(true);
        clone.style.width = '800px';
        clone.style.position = 'absolute';
        clone.style.left = '-9999px';
        document.body.appendChild(clone);

        // Apply enhanced styles to clone
        clone.style.background = 'linear-gradient(145deg, #1a2942 0%, #2c3e50 100%)';
        clone.style.padding = '40px';
        clone.style.color = '#ffffff';

        // Style the header in clone
        const header = clone.querySelector('.print-header');
        if (header) {
          header.style.background = 'rgba(255, 255, 255, 0.1)';
          header.style.color = 'white';
          header.style.padding = '30px';
          header.style.margin = '-40px -40px 30px -40px';
          header.style.borderRadius = '20px 20px 0 0';
        }

        // Center and style the image in clone
        const imageContainer = clone.querySelector('.uploaded-image-container');
        if (imageContainer) {
          imageContainer.style.textAlign = 'center';
          imageContainer.style.margin = '30px auto';
          imageContainer.style.background = 'rgba(255, 255, 255, 0.05)';
          imageContainer.style.padding = '20px';
          imageContainer.style.borderRadius = '15px';
          imageContainer.style.border = '1px solid rgba(255, 255, 255, 0.1)';
          
          const image = imageContainer.querySelector('.uploaded-image');
          if (image) {
            image.style.maxWidth = '80%';
            image.style.margin = '0 auto';
            image.style.display = 'block';
            image.style.borderRadius = '8px';
          }
        }

        // Style the info section in clone
        const infoSection = clone.querySelector('.info');
        if (infoSection) {
          infoSection.style.background = 'rgba(255, 255, 255, 0.05)';
          infoSection.style.padding = '25px';
          infoSection.style.borderRadius = '15px';
          infoSection.style.border = '1px solid rgba(255, 255, 255, 0.1)';
          
          const paragraphs = infoSection.querySelectorAll('p');
          paragraphs.forEach(p => {
            p.style.background = 'rgba(255, 255, 255, 0.05)';
            p.style.padding = '15px';
            p.style.margin = '0 0 8px 0';
            p.style.borderRadius = '8px';
            p.style.border = '1px solid rgba(255, 255, 255, 0.1)';
            p.style.color = '#ffffff';
          });
        }

        // Wait for images to load in clone
        const images = clone.getElementsByTagName('img');
        await Promise.all([...images].map(img => {
          if (img.complete) return Promise.resolve();
          return new Promise(resolve => {
            img.onload = resolve;
            img.onerror = resolve;
          });
        }));

        // Create canvas with better quality settings
        const canvas = await html2canvas(clone, {
          scale: 2,
          logging: false,
          useCORS: true,
          allowTaint: true,
          backgroundColor: null,
          imageTimeout: 0,
          onclone: (clonedDoc) => {
            const clonedElement = clonedDoc.querySelector('.print-section');
            if (clonedElement) {
              clonedElement.style.transform = 'none';
              clonedElement.style.margin = '0 auto';
              clonedElement.style.padding = '40px';
              clonedElement.style.background = 'linear-gradient(145deg, #1a2942 0%, #2c3e50 100%)';
            }
          }
        });

        // Remove the clone after canvas creation
        document.body.removeChild(clone);
        
        const imgData = canvas.toDataURL('image/jpeg', 1.0);
        
        // Initialize jsPDF with A4 size
        const { jsPDF } = window.jspdf;
        const pdf = new jsPDF({
          orientation: 'portrait',
          unit: 'mm',
          format: 'a4',
          compress: true
        });
        
        // Calculate dimensions to fit A4 page with proper margins
        const pageWidth = pdf.internal.pageSize.getWidth();
        const pageHeight = pdf.internal.pageSize.getHeight();
        const margin = 20;
        const contentWidth = pageWidth - (margin * 2);
        const contentHeight = (canvas.height * contentWidth) / canvas.width;
        
        // Add content
        pdf.addImage(imgData, 'JPEG', margin, margin, contentWidth, contentHeight);
        
        // Add page numbers if content spans multiple pages
        if (contentHeight > (pageHeight - (margin * 2))) {
          const pageCount = Math.ceil(contentHeight / (pageHeight - (margin * 2)));
          for (let i = 1; i <= pageCount; i++) {
            pdf.setFontSize(10);
            pdf.setTextColor(74, 144, 226);
            pdf.text(`Page ${i} of ${pageCount}`, pageWidth / 2, pageHeight - 10, {
              align: 'center'
            });
            if (i < pageCount) {
              pdf.addPage();
            }
          }
        }
        
        pdf.save('face-analysis-report.pdf');
      } catch (error) {
        console.error('Error generating PDF:', error);
        alert('Failed to generate PDF. Please try again.');
      }
    }

    async function downloadCrowdAnalysisPDF() {
      try {
        const element = document.getElementById('crowdReport');
        
        // Create a clone of the element for PDF generation
        const clone = element.cloneNode(true);
        clone.style.width = '800px';
        clone.style.position = 'absolute';
        clone.style.left = '-9999px';
        document.body.appendChild(clone);

        // Apply enhanced styles to clone
        clone.style.background = 'linear-gradient(145deg, #1a2942 0%, #2c3e50 100%)';
        clone.style.padding = '40px';
        clone.style.color = '#ffffff';

        // Style the header in clone
        const header = clone.querySelector('.print-header');
        if (header) {
          header.style.background = 'rgba(255, 255, 255, 0.1)';
          header.style.color = 'white';
          header.style.padding = '30px';
          header.style.margin = '-40px -40px 30px -40px';
          header.style.borderRadius = '20px 20px 0 0';
        }

        // Center and style the image in clone
        const imageContainer = clone.querySelector('.uploaded-image-container');
        if (imageContainer) {
          imageContainer.style.textAlign = 'center';
          imageContainer.style.margin = '30px auto';
          imageContainer.style.background = 'rgba(255, 255, 255, 0.05)';
          imageContainer.style.padding = '20px';
          imageContainer.style.borderRadius = '15px';
          imageContainer.style.border = '1px solid rgba(255, 255, 255, 0.1)';
          
          const image = imageContainer.querySelector('.uploaded-image');
          if (image) {
            image.style.maxWidth = '80%';
            image.style.margin = '0 auto';
            image.style.display = 'block';
            image.style.borderRadius = '8px';
          }
        }

        // Style the info section in clone
        const infoSection = clone.querySelector('.info');
        if (infoSection) {
          infoSection.style.background = 'rgba(255, 255, 255, 0.05)';
          infoSection.style.padding = '25px';
          infoSection.style.borderRadius = '15px';
          infoSection.style.border = '1px solid rgba(255, 255, 255, 0.1)';
          
          const paragraphs = infoSection.querySelectorAll('p');
          paragraphs.forEach(p => {
            p.style.background = 'rgba(255, 255, 255, 0.05)';
            p.style.padding = '15px';
            p.style.margin = '0 0 8px 0';
            p.style.borderRadius = '8px';
            p.style.border = '1px solid rgba(255, 255, 255, 0.1)';
            p.style.color = '#ffffff';
          });

          // Style crowd stats
          const crowdStats = infoSection.querySelector('.crowd-stats');
          if (crowdStats) {
            crowdStats.style.display = 'grid';
            crowdStats.style.gridTemplateColumns = 'repeat(3, 1fr)';
            crowdStats.style.gap = '15px';
            crowdStats.style.margin = '20px 0';

            const statDivs = crowdStats.querySelectorAll('div');
            statDivs.forEach(div => {
              div.style.background = 'rgba(255, 255, 255, 0.05)';
              div.style.border = '1px solid rgba(255, 255, 255, 0.1)';
              div.style.borderRadius = '8px';
              div.style.padding = '15px';
              div.style.textAlign = 'center';
            });
          }

          // Style additional stats
          const additionalStats = infoSection.querySelector('.additional-stats');
          if (additionalStats) {
            additionalStats.style.marginTop = '20px';
            additionalStats.style.paddingTop = '20px';
            additionalStats.style.borderTop = '1px solid rgba(255, 255, 255, 0.1)';
          }
        }

        // Wait for images to load in clone
        const images = clone.getElementsByTagName('img');
        await Promise.all([...images].map(img => {
          if (img.complete) return Promise.resolve();
          return new Promise(resolve => {
            img.onload = resolve;
            img.onerror = resolve;
          });
        }));

        // Create canvas with better quality settings
        const canvas = await html2canvas(clone, {
          scale: 2,
          logging: false,
          useCORS: true,
          allowTaint: true,
          backgroundColor: null,
          imageTimeout: 0,
          onclone: (clonedDoc) => {
            const clonedElement = clonedDoc.querySelector('.print-section');
            if (clonedElement) {
              clonedElement.style.transform = 'none';
              clonedElement.style.margin = '0 auto';
              clonedElement.style.padding = '40px';
              clonedElement.style.background = 'linear-gradient(145deg, #1a2942 0%, #2c3e50 100%)';
            }
          }
        });

        // Remove the clone after canvas creation
        document.body.removeChild(clone);
        
        const imgData = canvas.toDataURL('image/jpeg', 1.0);
        
        // Initialize jsPDF with A4 size
        const { jsPDF } = window.jspdf;
        const pdf = new jsPDF({
          orientation: 'portrait',
          unit: 'mm',
          format: 'a4',
          compress: true
        });
        
        // Calculate dimensions to fit A4 page with proper margins
        const pageWidth = pdf.internal.pageSize.getWidth();
        const pageHeight = pdf.internal.pageSize.getHeight();
        const margin = 20;
        const contentWidth = pageWidth - (margin * 2);
        const contentHeight = (canvas.height * contentWidth) / canvas.width;
        
        // Add content
        pdf.addImage(imgData, 'JPEG', margin, margin, contentWidth, contentHeight);
        
        // Add page numbers if content spans multiple pages
        if (contentHeight > (pageHeight - (margin * 2))) {
          const pageCount = Math.ceil(contentHeight / (pageHeight - (margin * 2)));
          for (let i = 1; i <= pageCount; i++) {
            pdf.setFontSize(10);
            pdf.setTextColor(74, 144, 226);
            pdf.text(`Page ${i} of ${pageCount}`, pageWidth / 2, pageHeight - 10, {
              align: 'center'
            });
            if (i < pageCount) {
              pdf.addPage();
            }
          }
        }
        
        pdf.save('crowd-analysis-report.pdf');
      } catch (error) {
        console.error('Error generating PDF:', error);
        alert('Failed to generate PDF. Please try again.');
      }
    }

    function updateReportDateTime(elementId) {
      const now = new Date();
      const options = { 
        year: 'numeric', 
        month: 'long', 
        day: 'numeric', 
        hour: '2-digit', 
        minute: '2-digit',
        second: '2-digit'
      };
      document.getElementById(elementId).textContent = 
        'Report Generated: ' + now.toLocaleDateString('en-US', options);
    }

    function redirectToLogin() {
      window.location.href = "login.html";
    }

    // Initialize drag and drop on page load
    document.addEventListener('DOMContentLoaded', initDragAndDrop);

