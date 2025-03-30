# Homepage.py
import streamlit as st

def homepage():
    st.set_page_config(
        page_title="Homepage",
        page_icon="🏠",
    )

    st.title("Homepage")
    st.text("Welcome to our P2P Network frontpage.")
    st.text("We hope you feel welcome.")
    st.subheader("P2P Network Overview")
    st.write("If you want to skip to the code click the Code button in the sidebar.")
    st.write("We created a simple P2P network application that allows users to share files with each other. The application uses sockets to establish connections between peers and transfer files.")

    st.sidebar.success("Select a page")
