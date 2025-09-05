import streamlit as st

st.title("DataDesk")

col1, col2 = st.columns([2, 1])

with col1:
    st.subheader("A ticket System Created by ADVANTEC")
    st.markdown("""
    Streamline your support operations with our comprehensive ticket management solution.
    Built for efficiency, designed for scale.
    """)

with col2:
    st.info("🚀 **Getting Started**\nCreate your first ticket to begin managing your support workflow.")