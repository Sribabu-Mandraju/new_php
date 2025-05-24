<?php
session_start();

// Error reporting for development (remove in production)
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Check if user is logged in
if (!isset($_SESSION['email'])) {
    header("Location: login.html");
    exit();
}

// Database configuration
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_NAME', 'project');
define('DB_CHARSET', 'utf8mb4');

// Improved database connection with error handling
try {
    $db = mysqli_connect(DB_HOST, DB_USER, DB_PASS, DB_NAME);
    
    if (!$db) {
        throw new Exception("Connection failed: " . mysqli_connect_error());
    }
    
    // Set proper character set
    if (!mysqli_set_charset($db, DB_CHARSET)) {
        throw new Exception("Error setting character set: " . mysqli_error($db));
    }
    
    // Set connection timeout
    mysqli_options($db, MYSQLI_OPT_CONNECT_TIMEOUT, 5);
    
} catch (Exception $e) {
    die("Database connection failed: " . $e->getMessage());
}

// Function to sanitize input
function sanitize_input($data) {
    global $db;
    return mysqli_real_escape_string($db, trim($data));
}

// Function to handle database errors
function handle_db_error($error) {
    error_log("Database error: " . $error);
    return "An error occurred. Please try again later.";
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Masked Intel - Dashboard</title>
  <link rel="stylesheet" href="styles.css" />
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>

  <script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script>
  <script src="https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js"></script>
  <style>
    .dashboard-container {
      padding: 2rem;
      display: grid;
      gap: 2rem;
      max-width: 1400px;
      margin: 0 auto;
    }

    .analysis-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
      gap: 2rem;
    }

    .analysis-card {
      background: rgba(255, 255, 255, 0.1);
      backdrop-filter: blur(10px);
      border-radius: 20px;
      padding: 2rem;
      border: 3px solid rgba(255, 255, 255, 0.1);
      transition: all 0.3s ease;
    }

    .analysis-card:hover {
      transform: translateY(-5px);
      border-color: rgba(255, 255, 255, 0.2);
      box-shadow: 0 10px 20px rgba(0, 0, 0, 0.2);
    }

    .analysis-card h2 {
      color: #fff;
      font-size: 1.8rem;
      margin-bottom: 1.5rem;
      text-align: center;
      position: relative;
    }

    .analysis-card h2::after {
      content: '';
      position: absolute;
      bottom: -8px;
      left: 50%;
      transform: translateX(-50%);
      width: 60px;
      height: 3px;
      background: linear-gradient(90deg, #4a90e2, #357abd);
      border-radius: 2px;
    }

    .upload-section {
      text-align: center;
      padding: 2rem;
      border: 2px dashed rgba(255, 255, 255, 0.2);
      border-radius: 15px;
      margin-bottom: 1.5rem;
      transition: all 0.3s ease;
      position: relative;
    }

    .upload-section.drag-over {
      border-color: #4a90e2;
      background: rgba(74, 144, 226, 0.1);
    }

    .upload-section.loading::after {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.7);
      border-radius: 15px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.5rem;
      color: white;
    }

    .upload-section.loading::before {
      content: 'Analyzing...';
      position: absolute;
      top: 50%;
      left: 50%;
      transform: translate(-50%, -50%);
      z-index: 1;
      color: white;
      font-size: 1.2rem;
    }

    .preview-container {
      display: none;
      margin: 1rem 0;
    }

    .preview-container img {
      max-width: 100%;
      max-height: 300px;
      border-radius: 10px;
      border: 2px solid rgba(255, 255, 255, 0.1);
    }

    .error-message {
      color: #ff4444;
      background: rgba(255, 68, 68, 0.1);
      padding: 1rem;
      border-radius: 8px;
      margin: 1rem 0;
      display: none;
    }

    .placeholder-img {
      width: 150px;
      height: 150px;
      object-fit: cover;
      border-radius: 15px;
      margin-bottom: 1rem;
      border: 2px solid rgba(255, 255, 255, 0.1);
    }

    .upload-section p {
      color: rgba(255, 255, 255, 0.8);
      margin-bottom: 1rem;
      font-size: 1.1rem;
    }

    .file-input-wrapper {
      position: relative;
      display: inline-block;
    }

    .file-input {
      opacity: 0;
      position: absolute;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      cursor: pointer;
    }

    .upload-btn {
      background: linear-gradient(135deg, #4a90e2 0%, #357abd 100%);
      color: white;
      padding: 0.8rem 1.5rem;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      font-size: 1rem;
      display: inline-flex;
      align-items: center;
      gap: 0.5rem;
      transition: all 0.3s ease;
    }

    .upload-btn:hover {
      transform: translateY(-2px);
      box-shadow: 0 4px 15px rgba(74, 144, 226, 0.3);
    }

    .result-box {
      display: none;
      background: rgba(0, 0, 0, 0.2);
      border-radius: 15px;
      padding: 1.5rem;
      margin-top: 1.5rem;
      text-align: center;
    }

    .result-box img {
      width: 100%;
      max-width: 400px;
      border-radius: 10px;
      margin: 1rem auto;
      display: block;
      object-fit: contain;
    }

    .uploaded-image-container {
      width: 100%;
      max-width: 600px;
      margin: 30px auto;
      text-align: center;
      padding: 20px;
      background: #f8f8f8;
      border-radius: 12px;
      box-shadow: 0 2px 10px rgba(0, 0, 0, 0.1);
    }

    .uploaded-image {
      width: auto;
      max-width: 100%;
      height: auto;
      max-height: 500px;
      border-radius: 8px;
      margin: 0 auto;
      display: block;
      object-fit: contain;
    }

    .action-buttons {
      display: flex;
      flex-direction: column;
      gap: 1rem;
      max-width: 300px;
      margin: 1.5rem auto 0;
    }

    .result-box .info {
      color: #fff;
    }

    .info p {
      margin: 0.5rem 0;
      font-size: 1.1rem;
      display: flex;
      justify-content: space-between;
      padding: 0.5rem 0;
      border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    }

    .info p strong {
      color: #4a90e2;
    }

    .crowd-stats {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 1rem;
      margin-top: 1.5rem;
      text-align: center;
    }

    .crowd-stats div {
      background: rgba(255, 255, 255, 0.1);
      padding: 1rem;
      border-radius: 10px;
    }

    .crowd-stats strong {
      font-size: 1.8rem;
      color: #4a90e2;
      display: block;
      margin-bottom: 0.5rem;
    }

    .match-btn {
      background: linear-gradient(135deg, #ff6b6b 0%, #ee5253 100%);
      color: white;
      padding: 0.8rem 1.5rem;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      width: 100%;
      margin-top: 1rem;
      font-size: 1rem;
      transition: all 0.3s ease;
    }

    .match-btn:hover {
      transform: translateY(-2px);
      box-shadow: 0 4px 15px rgba(238, 82, 83, 0.3);
    }

    .print-btn {
      background: linear-gradient(135deg, #2ecc71 0%, #27ae60 100%);
      color: white;
      padding: 0.8rem 1.5rem;
      border: none;
      border-radius: 8px;
      cursor: pointer;
      width: 100%;
      margin-top: 1rem;
      font-size: 1rem;
      transition: all 0.3s ease;
      display: flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
    }

    .print-btn:hover {
      transform: translateY(-2px);
      box-shadow: 0 4px 15px rgba(46, 204, 113, 0.3);
    }

    @media (max-width: 768px) {
      .dashboard-container {
        padding: 1rem;
      }

      .analysis-grid {
        grid-template-columns: 1fr;
      }

      .analysis-card h2 {
        font-size: 1.5rem;
      }
    }

    /* Print-specific styles */
    @media print {
      body {
        background: #ffffff !important;
        margin: 0 !important;
        padding: 0 !important;
      }

      .print-section {
        background: #ffffff !important;
        box-shadow: none !important;
        margin: 0 !important;
        padding: 20px !important;
        width: 100% !important;
        max-width: none !important;
      }

      .print-header {
        background: #4a90e2 !important;
        color: white !important;
        padding: 20px !important;
        margin: -20px -20px 20px -20px !important;
        border-radius: 0 !important;
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
      }

      .print-header h2 {
        color: white !important;
        font-size: 24px !important;
        margin: 0 !important;
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
      }

      .print-datetime {
        color: rgba(255, 255, 255, 0.9) !important;
        font-size: 12px !important;
        margin-top: 5px !important;
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
      }

      .uploaded-image-container {
        background: #f8f9fe !important;
        border: 1px solid #e1e8f0 !important;
        border-radius: 8px !important;
        padding: 15px !important;
        margin: 20px auto !important;
        max-width: 500px !important;
        text-align: center !important;
      }

      .uploaded-image {
        max-width: 100% !important;
        height: auto !important;
        border-radius: 4px !important;
      }

      .info {
        background: white !important;
        border: 1px solid #e1e8f0 !important;
        border-radius: 8px !important;
        padding: 20px !important;
        margin-top: 20px !important;
      }

      .info p {
        background: #f8f9fe !important;
        border: 1px solid #e1e8f0 !important;
        border-radius: 6px !important;
        padding: 12px 15px !important;
        margin: 0 0 8px 0 !important;
        color: #2c3e50 !important;
        display: flex !important;
        justify-content: space-between !important;
        align-items: center !important;
      }

      .info p:last-child {
        margin-bottom: 0 !important;
      }

      .info strong {
        color: #2c3e50 !important;
        font-size: 14px !important;
        font-weight: 600 !important;
        min-width: 120px !important;
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
      }

      .result-value {
        flex: 1 !important;
        text-align: right !important;
        margin-right: 15px !important;
        color: #2c3e50 !important;
        font-size: 14px !important;
      }

      .confidence {
        background: #4a90e2 !important;
        color: white !important;
        padding: 4px 12px !important;
        border-radius: 15px !important;
        font-size: 12px !important;
        font-weight: 500 !important;
        min-width: 60px !important;
        text-align: center !important;
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
      }

      .crowd-stats {
        display: grid !important;
        grid-template-columns: repeat(3, 1fr) !important;
        gap: 15px !important;
        margin: 20px 0 !important;
      }

      .crowd-stats div {
        background: #f8f9fe !important;
        border: 1px solid #e1e8f0 !important;
        border-radius: 6px !important;
        padding: 15px !important;
        text-align: center !important;
      }

      .crowd-stats strong {
        color: #4a90e2 !important;
        font-size: 20px !important;
        display: block !important;
        margin-bottom: 5px !important;
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
      }

      .additional-stats {
        margin-top: 20px !important;
        padding-top: 20px !important;
        border-top: 1px solid #e1e8f0 !important;
      }

      .no-print {
        display: none !important;
      }

      /* Ensure all colors print correctly */
      * {
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
      }
    }

    .confidence {
      font-size: 0.85rem;
      color: #4a90e2;
      margin-left: 0.5rem;
      font-weight: 500;
    }

    .crowd-stats .confidence {
      display: block;
      margin-top: 0.5rem;
      font-size: 0.8rem;
    }

    .additional-stats {
      margin-top: 2rem;
      padding-top: 1rem;
      border-top: 1px solid rgba(255, 255, 255, 0.1);
    }

    .print-header {
      text-align: center;
      margin-bottom: 2rem;
      padding-bottom: 1rem;
      border-bottom: 2px solid rgba(255, 255, 255, 0.1);
    }

    .report-logo {
      max-width: 200px;
      margin-bottom: 1rem;
    }

    .print-datetime {
      color: rgba(255, 255, 255, 0.7);
      font-size: 0.9rem;
      margin-top: 0.5rem;
    }

    @media print {
      body {
        background: white;
        color: black;
      }

      .analysis-card {
        background: none;
        border: none;
        box-shadow: none;
      }

      .no-print {
        display: none !important;
      }

      .print-header {
        border-bottom-color: rgba(0, 0, 0, 0.1);
      }

      .info p {
        color: black;
        border-bottom-color: rgba(0, 0, 0, 0.1);
      }

      .confidence {
        color: #357abd;
      }

      .additional-stats {
        border-top-color: rgba(0, 0, 0, 0.1);
      }
    }

    @keyframes fadeInUp {
      from {
        opacity: 0;
        transform: translateY(20px);
      }

      to {
        opacity: 1;
        transform: translateY(0);
      }
    }

    .modal-animate {
      animation: fadeInUp 0.3s ease-out;
    }

    .loading {
      position: relative;
      pointer-events: none;
    }

    .loading::after {
      content: '';
      position: absolute;
      top: 50%;
      left: 50%;
      width: 30px;
      height: 30px;
      margin: -15px 0 0 -15px;
      border: 3px solid rgba(74, 144, 226, 0.3);
      border-top-color: #4a90e2;
      border-radius: 50%;
      animation: spin 1s linear infinite;
    }

    @keyframes spin {
      to {
        transform: rotate(360deg);
      }
    }

    /* Enhanced PDF and report styles */
    .print-section {
      background: linear-gradient(135deg, #f8f9fe 0%, #ffffff 100%);
      padding: 30px;
      max-width: 800px;
      margin: 0 auto;
      border-radius: 15px;
      box-shadow: 0 5px 15px rgba(0, 0, 0, 0.05);
    }

    .print-header {
      text-align: center;
      margin-bottom: 30px;
      padding-bottom: 20px;
      border-bottom: 2px solid #4a90e2;
      background: linear-gradient(135deg, #4a90e2 0%, #357abd 100%);
      margin: -30px -30px 30px -30px;
      padding: 30px;
      border-radius: 15px 15px 0 0;
      color: white;
    }

    .print-header h2 {
      color: white;
      font-size: 28px;
      margin-bottom: 10px;
      text-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
    }

    .print-datetime {
      color: rgba(255, 255, 255, 0.9);
      font-size: 14px;
      font-weight: 500;
    }

    .uploaded-image-container {
      width: 100%;
      max-width: 600px;
      margin: 30px auto;
      text-align: center;
      padding: 20px;
      background: linear-gradient(135deg, #ffffff 0%, #f8f9fe 100%);
      border-radius: 12px;
      box-shadow: 0 3px 15px rgba(0, 0, 0, 0.08);
      border: 1px solid rgba(74, 144, 226, 0.1);
    }

    .info {
      margin-top: 30px;
      border-radius: 12px;
      padding: 25px;
      background: linear-gradient(135deg, #ffffff 0%, #f8f9fe 100%);
      box-shadow: 0 3px 15px rgba(0, 0, 0, 0.08);
      border: 1px solid rgba(74, 144, 226, 0.1);
    }

    .info p {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 15px;
      margin: 0;
      border-bottom: 1px solid rgba(74, 144, 226, 0.1);
      background: white;
      border-radius: 8px;
      margin-bottom: 8px;
    }

    .info p:last-child {
      border-bottom: none;
      margin-bottom: 0;
    }

    .info strong {
      color: #2c3e50;
      font-weight: 600;
      font-size: 15px;
    }

    .confidence {
      background: linear-gradient(135deg, #4a90e2 0%, #357abd 100%);
      -webkit-background-clip: text;
      background-clip: text;
      -webkit-text-fill-color: transparent;
      font-weight: 600;
      font-size: 14px;
      padding: 4px 8px;
      border-radius: 4px;
      border: 1px solid rgba(74, 144, 226, 0.2);
    }

    .crowd-stats {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 15px;
      margin: 25px 0;
    }

    .crowd-stats div {
      background: linear-gradient(135deg, #ffffff 0%, #f8f9fe 100%);
      padding: 20px;
      border-radius: 12px;
      box-shadow: 0 3px 10px rgba(0, 0, 0, 0.05);
      border: 1px solid rgba(74, 144, 226, 0.1);
      text-align: center;
    }

    .crowd-stats strong {
      font-size: 24px;
      color: #4a90e2;
      display: block;
      margin-bottom: 8px;
    }

    .additional-stats {
      margin-top: 25px;
      padding-top: 25px;
      border-top: 2px solid rgba(74, 144, 226, 0.1);
    }

    /* Enhanced Face Recognition Report Styles */
    #faceReport {
      background: linear-gradient(145deg, #1a2942 0%, #2c3e50 100%);
      padding: 30px;
      border-radius: 20px;
      color: #ffffff;
    }

    #faceReport .print-header {
      background: rgba(255, 255, 255, 0.1);
      margin: -30px -30px 30px -30px;
      padding: 25px;
      border-radius: 20px 20px 0 0;
      text-align: center;
    }

    #faceReport .print-header h2 {
      color: #4a90e2;
      font-size: 24px;
      margin: 0;
      font-weight: 600;
    }

    #faceReport .print-datetime {
      color: rgba(255, 255, 255, 0.8);
      font-size: 12px;
      margin-top: 15px;
      padding-bottom: 5px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    }

    #faceReport .uploaded-image-container {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 15px;
      padding: 20px;
      margin: 20px auto;
      max-width: 400px;
      text-align: center;
    }

    #faceReport .uploaded-image {
      max-width: 100%;
      height: auto;
      border-radius: 8px;
    }

    #faceReport .info {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 15px;
      padding: 20px;
    }

    #faceReport .info p {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 15px;
      margin: 0 0 10px 0;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 8px;
    }

    #faceReport .info p:last-child {
      margin-bottom: 0;
    }

    #faceReport .info strong {
      color: #4a90e2;
      font-size: 14px;
      font-weight: 600;
      min-width: 120px;
    }

    #faceReport .result-value {
      flex: 1;
      text-align: right;
      margin-right: 15px;
      color: #ffffff;
      font-size: 14px;
    }

    #faceReport .confidence {
      color: white;
      background: #4a90e2;
      padding: 4px 12px;
      border-radius: 15px;
      font-size: 12px;
      font-weight: 500;
      min-width: 60px;
      text-align: center;
    }

    @media print {
      #faceReport {
        background: linear-gradient(145deg, #1a2942 0%, #2c3e50 100%) !important;
        color: #ffffff !important;
        padding: 20px !important;
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
      }

      #faceReport .print-header {
        background: rgba(255, 255, 255, 0.1) !important;
        margin: -20px -20px 20px -20px !important;
        padding: 20px !important;
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
      }

      #faceReport .print-header h2 {
        color: #4a90e2 !important;
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
      }

      #faceReport .print-datetime {
        color: rgba(255, 255, 255, 0.8) !important;
        font-size: 12px !important;
        margin-top: 15px !important;
        padding-bottom: 5px !important;
        border-bottom: 1px solid rgba(255, 255, 255, 0.1) !important;
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
      }

      #faceReport .uploaded-image-container {
        background: rgba(255, 255, 255, 0.05) !important;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
      }

      #faceReport .info {
        background: rgba(255, 255, 255, 0.05) !important;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
      }

      #faceReport .info p {
        background: rgba(255, 255, 255, 0.05) !important;
        border: 1px solid rgba(255, 255, 255, 0.1) !important;
        color: #ffffff !important;
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
      }

      #faceReport .info strong {
        color: #4a90e2 !important;
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
      }

      #faceReport .result-value {
        color: #ffffff !important;
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
      }

      #faceReport .confidence {
        background: #4a90e2 !important;
        color: white !important;
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
      }

      .no-print {
        display: none !important;
      }
    }

    /* Enhanced Crowd Analysis Report Styles */
    #crowdReport {
      background: linear-gradient(145deg, #1a2942 0%, #2c3e50 100%);
      padding: 30px;
      border-radius: 20px;
      color: #ffffff;
      width: 100%;
      max-width: 800px;
      margin: 0 auto;
    }

    #crowdReport .print-header {
      background: rgba(255, 255, 255, 0.1);
      margin: -30px -30px 30px -30px;
      padding: 25px;
      border-radius: 20px 20px 0 0;
      text-align: center;
    }

    #crowdReport .print-header h2 {
      color: #4a90e2;
      font-size: 24px;
      margin: 0;
      font-weight: 600;
    }

    #crowdReport .print-datetime {
      color: rgba(255, 255, 255, 0.8);
      font-size: 12px;
      margin-top: 15px;
      padding-bottom: 5px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    }

    #crowdReport .uploaded-image-container {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 15px;
      padding: 20px;
      margin: 20px auto;
      width: 100%;
      max-width: 600px;
      text-align: center;
      display: flex;
      justify-content: center;
      align-items: center;
    }

    #crowdReport .uploaded-image {
      max-width: 100%;
      height: auto;
      max-height: 400px;
      border-radius: 8px;
      object-fit: contain;
    }

    #crowdReport .info {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 15px;
      padding: 20px;
      margin-top: 20px;
    }

    #crowdReport .info p {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 15px;
      margin: 0 0 10px 0;
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 8px;
    }

    #crowdReport .info p:last-child {
      margin-bottom: 0;
    }

    #crowdReport .info strong {
      color: #4a90e2;
      font-size: 14px;
      font-weight: 600;
      min-width: 120px;
    }

    #crowdReport .result-value {
      flex: 1;
      text-align: right;
      margin-right: 15px;
      color: #ffffff;
      font-size: 14px;
    }

    #crowdReport .crowd-stats {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 15px;
      margin: 20px 0;
    }

    #crowdReport .crowd-stats div {
      background: rgba(255, 255, 255, 0.05);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 8px;
      padding: 15px;
      text-align: center;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
    }

    #crowdReport .crowd-stats strong {
      color: #4a90e2;
      font-size: 24px;
      display: block;
      margin-bottom: 8px;
    }

    #crowdReport .crowd-stats .result-value {
      color: rgba(255, 255, 255, 0.9);
      font-size: 13px;
      margin: 0;
      text-align: center;
    }

    #crowdReport .additional-stats {
      margin-top: 20px;
      padding-top: 20px;
      border-top: 1px solid rgba(255, 255, 255, 0.1);
    }

    @media print {
      #crowdReport {
        background: linear-gradient(145deg, #1a2942 0%, #2c3e50 100%) !important;
        color: #ffffff !important;
        padding: 20px !important;
        width: 100% !important;
        max-width: 800px !important;
        margin: 0 auto !important;
        -webkit-print-color-adjust: exact !important;
        print-color-adjust: exact !important;
      }

      #crowdReport .uploaded-image-container {
        width: 100% !important;
        max-width: 600px !important;
        margin: 20px auto !important;
        display: flex !important;
        justify-content: center !important;
        align-items: center !important;
      }

      #crowdReport .uploaded-image {
        max-width: 100% !important;
        height: auto !important;
        max-height: 400px !important;
        object-fit: contain !important;
      }

      #crowdReport .crowd-stats {
        display: grid !important;
        grid-template-columns: repeat(3, 1fr) !important;
        gap: 15px !important;
        margin: 20px 0 !important;
      }

      #crowdReport .crowd-stats div {
        display: flex !important;
        flex-direction: column !important;
        align-items: center !important;
        justify-content: center !important;
      }

      #crowdReport .crowd-stats .result-value {
        text-align: center !important;
        margin: 0 !important;
      }
    }

    .example-image-card {
      width: 100%;
      max-width: 300px;
      margin: 0 auto 1.5rem;
      text-align: center;
      background: rgba(255, 255, 255, 0.05);
      padding: 1rem;
      border-radius: 15px;
      border: 1px solid rgba(255, 255, 255, 0.1);
      transition: all 0.3s ease;
      box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
    }

    .example-image-card:hover {
      transform: translateY(-5px);
      border-color: rgba(74, 144, 226, 0.5);
      box-shadow: 0 6px 12px rgba(0, 0, 0, 0.15);
    }

    .example-image-card img {
      width: 100%;
      height: 200px;
      object-fit: cover;
      border-radius: 10px;
    }

    @media (max-width: 768px) {
      .example-image-card {
        max-width: 250px;
      }

      .example-image-card img {
        height: 180px;
      }
    }
  </style>
</head>

<body>
  <div class="geometric-shapes">
    <div class="shape"></div>
    <div class="shape"></div>
    <div class="shape"></div>
    <div class="shape"></div>
    <div class="shape"></div>
  </div>

  <header class="navbar">
    <div class="logo">
      <span>MASKED INTEL</span>
    </div>

    <nav>
      <a href="about.html">About</a>
      <a href="features.html">Features</a>
      <a href="contact.html">Contact</a>
      <button class="nav-btn" onclick="redirectToLogin()">Logout</button>
    </nav>
  </header>

  <main class="dashboard-container">
    <div class="analysis-grid">
      <!-- Face Analysis Section -->
      <div class="analysis-card">
        <h2>Face Analysis</h2>
        <div class="example-image-card">
          <img src="face card.png" alt="Example Face" />
        </div>
        <div class="upload-section" id="facePlaceholder">
          <p>Upload a face image to detect personal attributes</p>
          <div class="file-input-wrapper">
            <input type="file" class="file-input" accept="image/*" onchange="analyzeFace()" />
            <button class="upload-btn">
              <i class="fas fa-upload"></i>
              Upload Image
            </button>
          </div>
          <div class="preview-container">
            <img src="" alt="Image preview" />
          </div>
        </div>

        <div class="result-box" id="faceResult">
          <div class="print-section" id="faceReport">
            <div class="print-header">
              <h2>Face Analysis Report</h2>
              <div class="print-datetime" id="faceReportDateTime"></div>
            </div>
            <div class="uploaded-image-container">
              <img id="uploadedFaceImage" class="uploaded-image" alt="Analyzed Face" />
            </div>
            <div class="info">
              <p>
                <strong>Authenticity</strong>
                <span class="result-value">Real</span>
              </p>
              <p>
                <strong>Age Range</strong>
                <span class="result-value">25-30 years</span>
              </p>
              <p>
                <strong>Gender</strong>
                <span class="result-value">Male</span>
              </p>
              <p>
                <strong>Emotion</strong>
                <span class="result-value">Neutral</span>
              </p>
              <p>
                <strong>Facial Hair</strong>
                <span class="result-value">No Beard</span>
              </p>
              <p>
                <strong>Eyewear</strong>
                <span class="result-value">No Glasses</span>
              </p>
              <p>
                <strong>Head Position</strong>
                <span class="result-value">Frontal</span>
              </p>
              <p>
                <strong>Eye Direction</strong>
                <span class="result-value">Center</span>
              </p>
            </div>
          </div>
          <div class="action-buttons no-print">
            <button class="match-btn">
              <i class="fas fa-search"></i>
              Match with Criminal Database
            </button>
            <button class="print-btn" onclick="downloadFaceAnalysisPDF()">
              <i class="fas fa-file-pdf"></i>
              Download PDF Report
            </button>
          </div>
        </div>
      </div>

      <!-- Crowd Analysis Section -->
      <div class="analysis-card">
        <h2>Crowd Analysis</h2>
        <div class="example-image-card">
          <img src="crowd card.png" alt="Example Crowd" />
        </div>
        <div class="upload-section" id="crowdPlaceholder">
          <p>Upload an image of a crowd to analyze mask compliance and headcount</p>
          <div class="file-input-wrapper">
            <input type="file" class="file-input" accept="image/*" onchange="analyzeCrowd()" />
            <button class="upload-btn">
              <i class="fas fa-upload"></i>
              Upload Image
            </button>
          </div>
          <div class="preview-container">
            <img src="" alt="Image preview" />
          </div>
        </div>

        <div class="result-box" id="crowdResult">
          <div class="print-section" id="crowdReport">
            <div class="print-header">
              <h2>Crowd Analysis Report</h2>
              <div class="print-datetime" id="crowdReportDateTime"></div>
            </div>
            <div class="uploaded-image-container">
              <img id="uploadedCrowdImage" class="uploaded-image" alt="Analyzed Crowd" />
            </div>
            <div class="info">
              <p>
                <strong>Crowd Status</strong>
                <span class="result-value">High Density</span>
              </p>
              <div class="crowd-stats">
                <div>
                  <strong>30</strong>
                  <span class="result-value">Total People</span>
                </div>
                <div>
                  <strong>15</strong>
                  <span class="result-value">Masked</span>
                </div>
                <div>
                  <strong>15</strong>
                  <span class="result-value">Unmasked</span>
                </div>
              </div>
              <div class="additional-stats">
                <p>
                  <strong>Social Distancing</strong>
                  <span class="result-value">Poor</span>
                </p>
                <p>
                  <strong>Flow Direction</strong>
                  <span class="result-value">Multi-directional</span>
                </p>
                <p>
                  <strong>Crowd Density</strong>
                  <span class="result-value">3 people/m²</span>
                </p>
              </div>
            </div>
          </div>
          <div class="action-buttons no-print">
            <button class="print-btn" onclick="downloadCrowdAnalysisPDF()">
              <i class="fas fa-file-pdf"></i>
              Download PDF Report
            </button>
          </div>
        </div>
      </div>
    </div>
  </main>

  <script>
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

          // Remove loading class to prevent duplicate text
          container.classList.remove('loading');
          const previewContainer = container.querySelector('.preview-container');
          previewContainer.style.display = 'none';

          // Simulate analysis delay
          await new Promise(resolve => setTimeout(resolve, 2000));

          // Show preview after analysis
          const imageData = await previewImage(file, previewContainer);
          previewContainer.style.display = 'block';

          // Hide the entire upload section and show results
          document.getElementById("facePlaceholder").style.display = "none";
          document.getElementById("faceResult").style.display = "block";
          document.getElementById("uploadedFaceImage").src = imageData;
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

          // Remove loading class to prevent duplicate text
          container.classList.remove('loading');
          const previewContainer = container.querySelector('.preview-container');
          previewContainer.style.display = 'none';

          // Simulate analysis delay
          await new Promise(resolve => setTimeout(resolve, 2000));

          // Show preview after analysis
          const imageData = await previewImage(file, previewContainer);
          previewContainer.style.display = 'block';

          // Hide the entire upload section and show results
          document.getElementById("crowdPlaceholder").style.display = "none";
          document.getElementById("crowdResult").style.display = "block";
          document.getElementById("uploadedCrowdImage").src = imageData;
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
        const {
          jsPDF
        } = window.jspdf;
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
        const {
          jsPDF
        } = window.jspdf;
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
  </script>
</body>

</html>