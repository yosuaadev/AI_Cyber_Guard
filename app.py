import os
import streamlit as st
import pandas as pd
import joblib

# ponytail: simple inline inference app; add model versioning & multi-class explainability when needed
st.set_page_config(page_title="AI Cyber Guard", page_icon="🛡️", layout="centered")

st.title("🛡️ AI Cyber Guard - Network Intrusion Detection")
st.write("Deteksi potensi serangan siber (DDoS vs BENIGN) berbasis AI.")

model_path = os.path.join(os.path.dirname(__file__), "model_security.pkl")

@st.cache_resource
def load_model():
    return joblib.load(model_path)

try:
    model = load_model()
    st.success("Model AI berhasil dimuat.")
except Exception as e:
    st.error(f"Gagal memuat model: {e}")
    st.stop()

st.subheader("Input Parameter Lalu Lintas Jaringan")

col1, col2 = st.columns(2)
with col1:
    dest_port = st.number_input("Destination Port", min_value=0, max_value=65535, value=80, step=1)
    flow_duration = st.number_input("Flow Duration (µs)", min_value=0, value=1000, step=10)

with col2:
    fwd_pkts = st.number_input("Total Forward Packets", min_value=0, value=2, step=1)
    bwd_pkts = st.number_input("Total Backward Packets", min_value=0, value=0, step=1)

if st.button("Jalankan Deteksi", type="primary"):
    features = ['Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets']
    input_df = pd.DataFrame([[dest_port, flow_duration, fwd_pkts, bwd_pkts]], columns=features)
    
    pred = model.predict(input_df)[0]
    prob = model.predict_proba(input_df)[0]
    classes = model.classes_
    
    st.divider()
    st.subheader("Hasil Analisis")
    
    if str(pred).upper() == "BENIGN":
        st.success(f"Status: **{pred}** (Aman / Normal Traffic)")
    else:
        st.error(f"Peringatan: **{pred}** (Terdeteksi Serangan!)")
        
    prob_df = pd.DataFrame({"Kategori": classes, "Probabilitas": [f"{p*100:.2f}%" for p in prob]})
    st.table(prob_df)
