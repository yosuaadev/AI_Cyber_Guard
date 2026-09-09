import streamlit as st
import pandas as pd
import joblib

# tampilan halaman web
st.set_page_config(page_title="AI CyberGuard SOC", page_icon="🛡️", layout="centered")

st.title("🛡️ AI CyberGuard - Network Intrusion")
st.subheader("Security Operations Center (SOC) Dashboard")
st.write("Sistem AI berbasis Random Forest untuk mendeteksi anomali lalu lintas jaringan dan serangan DDoS.")

st.divider()

# memanggil dan menyimpan model ai ke memori menggunakan chache
@st.cache_resource
def load_model():
    return joblib.load('model_security.pkl')
model = load_model()

# form inputan
st.markdown("### 🔍 Monitoring Parameter Jaringan")
col1, col2 = st.columns(2)

with col1:
    dest_port = st.number_input("Destination Port (Target)", min_value=0, max_value=65535, value=80, help="Contoh: 80 untuk HTTP, 443 untuk HTTPS")
    flow_duration = st.number_input("Flow Duration (Microseconds)", min_value=0, value=150000)

with col2:
    total_fwd = st.number_input("Total Fwd Packets", min_value=0, value=10)
    total_bwd = st.number_input("Total Backward Packets", min_value=0, value=8)

st.divider()

# tombol proses
if st.button("Analisis Trafik Jaringan", type="primary", use_container_width=True):
    # membugkus angka dari inputan user jadi format tabel (dataframe) sesuai data training
    input_data = pd.DataFrame([[dest_port, flow_duration, total_fwd, total_bwd]], 
                              columns=['Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets'])
    
    # cek status jaringan dari inputan user
    hasil = model.predict(input_data)[0]
    
    # menampilkan hasil
    if hasil == 'BENIGN':
        st.success("✅ **STATUS: LALU LINTAS AMAN (BENIGN)**")
        st.write("Aktivitas jaringan terdeteksi normal. Tidak ada indikasi serangan siber.")
    else:
        st.error("🚨 **CRITICAL WARNING: TERDETEKSI SERANGAN DDoS!**")
        st.write("AI mendeteksi anomali paket yang tidak wajar. Segera periksa *log* jaringan atau aktifkan protokol mitigasi!")