import numpy as np
import shap
import matplotlib.pyplot as plt
from flask import Flask, request, render_template, jsonify, send_file
import joblib
import os
import subprocess
import csv
from androguard.misc import AnalyzeAPK

app = Flask(__name__)

# Tải mô hình đã huấn luyện
model = joblib.load('drebin_model.pkl')

drebin_features = ['transact', 'onServiceConnected', 'bindService', 'attachInterface', 'ServiceConnection', 'android.os.Binder', 'SEND_SMS', 'Ljava.lang.Class.getCanonicalName', 'Ljava.lang.Class.getMethods', 'Ljava.lang.Class.cast', 'Ljava.net.URLDecoder', 'android.telephony.SmsManager', 'READ_PHONE_STATE', 'ClassLoader', 'Landroid.content.Context.registerReceiver', 'Ljava.lang.Class.getField', 'Landroid.content.Context.unregisterReceiver', 'GET_ACCOUNTS', 'RECEIVE_SMS', 'READ_SMS', 'android.intent.action.BOOT_COMPLETED', 'android.content.pm.PackageInfo', 'TelephonyManager.getLine1Number', 'HttpGet.init', 'android.telephony.gsm.SmsManager', 'WRITE_HISTORY_BOOKMARKS', 'TelephonyManager.getSubscriberId', 'INTERNET', 'TelephonyManager.getDeviceId', 'chmod', 'Runtime.exec', 'ACCESS_COARSE_LOCATION', 'Ljava.lang.Class.getResource', 'ACCESS_WIFI_STATE', 'WRITE_EXTERNAL_STORAGE']

def extract_features(apk_path):
    # Giải mã APK sử dụng APKTOOL
    decompiled_dir = 'decompiled_apk'
    if not os.path.exists(decompiled_dir):
        subprocess.run(['apktool', 'd', apk_path, '-o', decompiled_dir])

    # Phân tích APK với Androguard
    a, d, dx = AnalyzeAPK(apk_path)

    # Trích xuất các đặc trưng (quyền, thành phần, gọi API, hành động intent)
    permissions = a.get_permissions()
    components = {
        'activities': a.get_activities(),
        'services': a.get_services(),
        'receivers': a.get_receivers(),
        'providers': a.get_providers()
    }

    api_calls = set()
    intent_actions = set()
    for method in dx.get_methods():
        m = method.get_method()
        if not hasattr(m, 'get_instructions'):
            continue
        for instruction in m.get_instructions():
            op_value = instruction.get_op_value()
            if 0x6e <= op_value <= 0x72:
                try:
                    class_name, method_name, descriptor = instruction.get_operands()[0][2].split('->')
                    api_calls.add(f"{class_name}->{method_name}")
                except Exception as e:
                    pass
            elif op_value == 0x1a:
                try:
                    string_value = instruction.get_operands()[1][2]
                    if string_value.startswith('android.intent.action.'):
                        intent_actions.add(string_value)
                except Exception as e:
                    pass

    # Tạo vector đặc trưng
    feature_vector = [0] * len(drebin_features)
    
    # Kiểm tra quyền
    for permission in permissions:
        feature_name = permission.split('.')[-1]  # Trích xuất tên quyền
        if feature_name in drebin_features:
            index = drebin_features.index(feature_name)
            feature_vector[index] = 1
    
    # Kiểm tra thành phần
    for component_type, component_list in components.items():
        for component in component_list:
            if component in drebin_features:
                index = drebin_features.index(component)
                feature_vector[index] = 1
    
    # Kiểm tra gọi API
    for feature in api_calls:
        if feature in drebin_features:
            index = drebin_features.index(feature)
            feature_vector[index] = 1
    
    # Kiểm tra hành động intent
    for feature in intent_actions:
        if feature in drebin_features:
            index = drebin_features.index(feature)
            feature_vector[index] = 1

    csv_file = 'data_malware.csv'
    with open(csv_file, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(drebin_features)  # Ghi header
        writer.writerow(feature_vector)  # Ghi vector đặc trưng
    return feature_vector


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'Không có tệp'})
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'Không có tệp được chọn'})
    if file:
        file_path = os.path.join('uploads', file.filename)
        file.save(file_path)

        # Trích xuất các đặc trưng
        features = extract_features(file_path)
        # Dự đoán sử dụng mô hình
        prediction = model.predict([features])
        result = 'Malicious' if prediction[0] == 1 else 'Benign'
        print(f"Dự đoán: {result}")

        # Chuyển đổi các đặc trưng sang numpy array
        features_np = np.array(features).reshape(1, -1)

        # Tạo diễn giải SHAP
        explainer = shap.Explainer(model)
        shap_values = explainer(features_np)

        # Lấy giá trị SHAP cho lớp dự đoán 
        shap_values_der = shap_values.values
        shap_values_for_class = shap_values_der[:, :, 1] 

        shap.summary_plot(shap_values_for_class, features=features_np, feature_names=drebin_features, show=False)

        # Lưu biểu đồ
        plot_path = os.path.join('static', 'shap_summary.png')
        plt.savefig(plot_path)
        plt.close()

        # Hiển thị kết quả với dự đoán và biểu đồ SHAP
        return render_template('result.html', result=result)

if __name__ == '__main__':
    app.run(debug=True)
