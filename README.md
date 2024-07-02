# Explainable ML for Cybersecurity
## NT522.O21.ANTT.G6
To research and experiment the paper "Alani, M. M., & Awad, A. I. (2022). Paired: An explainable lightweight android malware detection system. IEEE Access, 10, 73214-73228." 
The project focuses on the critical task of detecting and preventing malware on Android devices using explainable machine learning (ML) techniques. Machine learning methods have shown high accuracy in malware detection but often rely on non-transparent features. This project aims to train classifiers for Android malware detection and use SHAP (SHapley Additive exPlanations) to explain the selected features, ensuring that high accuracy is derived from understandable conditions.

## Project Content
### PAIRED Model
PAIRED is a lightweight Android malware detection system that uses static features for quick decisions, ensuring high accuracy, low resource usage, and effective generalization. The model is activated whenever a new application is installed on an Android device.
### Dataset
Training Dataset: Drebin-215 with 15,036 instances (9476 benign, 5560 malicious) and 215 static features.
Test Datasets: Malgenome-215 and CICmalDroid2020 for evaluating model generalization.

## Experiment and Evaluation
Google Colab: For model development.
Python: Main programming language.
Flask: Web framework for the application.
SHAP: To generate explanation values.
APKTool: For decoding APK files.
Androguard: For feature extraction.
Scikit-learn: For building and training ML models.

## Demo
Run the Flask web server:
    ```bash
    python Web.py
    ```
Open a web browser and go to `http://127.0.0.1:5000`.
Upload an APK file to get the prediction and explanation.

## Project Structure
- `a.py`: The main Python script to run the Flask web application.
- `templates/`: Folder containing the HTML templates.
- `static/`: Folder containing static files like the explanation image.
- `uploads/`: Folder to store uploaded APK files.
