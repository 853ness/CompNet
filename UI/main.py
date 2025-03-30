# main.py
import streamlit as st

# Import the pages
from Homepage import Homepage
from Code import Code_page

# Sidebar navigation
st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", ["Homepage", "Code"])

# Display the selected page
if page == "homepage":
    homepage()
elif page == "code":
    code_page()
