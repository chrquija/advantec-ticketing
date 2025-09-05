import streamlit as st

# Hero Section
st.markdown("""
<div style="text-align: center; padding: 2rem; background: linear-gradient(90deg, #667eea 0%, #764ba2 100%); border-radius: 10px; margin-bottom: 2rem;">
    <h1 style="color: white; font-size: 3rem; margin-bottom: 0.5rem;">DataDesk</h1>
    <h3 style="color: white; font-weight: 300;">A ticket System Created by ADVANTEC</h3>
    <p style="color: white; font-size: 1.2rem; margin-top: 1rem;">Streamline your support workflow with our powerful ticket management system</p>
</div>
""", unsafe_allow_html=True)

# Quick overview
col1, col2 = st.columns(2)
with col1:
    st.markdown("### 🎯 **Purpose**")
    st.write("Efficiently manage customer support tickets from creation to resolution")

with col2:
    st.markdown("### ⚡ **Features**")
    st.write("Real-time tracking, team collaboration, and comprehensive reporting")