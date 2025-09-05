
import streamlit as st

st.title("DataDesk")
st.subheader("A ticket System Created by ADVANTEC")

st.markdown("---")

col1, col2, col3 = st.columns(3)
with col1:
    st.metric("Active Tickets", "12", "2")
with col2:
    st.metric("Resolved Today", "8", "-1")
with col3:
    st.metric("Response Time", "2.4h", "-0.3h")

st.markdown("---")
st.markdown("### Quick Actions")