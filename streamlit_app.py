import streamlit as st
from phishing_tool import analyze_url, analyze_email

st.set_page_config(page_title="Phishing Awareness Tool", page_icon="🔍", layout="centered")

st.markdown(
    """
    <style>
    [data-testid="stToolbar"] { display: none !important; }
    [data-testid="stDecoration"] { display: none !important; }
    [data-testid="stStatusWidget"] { display: none !important; }
    #MainMenu { visibility: hidden; }
    footer { visibility: hidden; }
    </style>
    """,
    unsafe_allow_html=True,
)

st.title("🔍 Phishing Awareness Tool")
mode = st.radio("Mode", ["URL", "Email"], horizontal=True)

if mode == "URL":
    with st.form("url_form"):
        url = st.text_input("Enter URL", placeholder="https://example.com/login")
        submitted = st.form_submit_button("Analyze URL", type="primary")
    if submitted and url:
        res = analyze_url(url)
        st.subheader("Verdict")
        if res.get("verdict") == "Dangerous":
            st.error("Dangerous")
        elif res.get("verdict") == "Suspicious":
            st.warning("Suspicious")
        else:
            st.success("Safe")

        st.subheader("Overall")
        if res.get("verdict") == "Safe":
            st.success("Safe")
        else:
            st.error("Not Safe")

        st.subheader("Details")
        details = {k: v for k, v in res.items() if k in ("input", "host", "registrable_domain", "tld") and v}
        for k, v in details.items():
            if k == "input" and isinstance(v, str) and v.startswith("http"):
                st.markdown(f"- **{k}**: [{v}]({v})")
            else:
                st.markdown(f"- **{k}**: {v}")
        st.subheader("Reasons")
        for r in res.get("reasons", []):
            st.write(f"- {r}")

else:
    with st.form("email_form"):
        email_text = st.text_area(
            "Paste email text (raw/plain or HTML)", height=240,
            placeholder="From: Support <support@example.com>\nSubject: Verify your account\n..."
        )
        submitted_email = st.form_submit_button("Analyze Email", type="primary")
    if submitted_email and email_text.strip():
        res = analyze_email(email_text)
        st.subheader("Verdict")
        if res.get("verdict") == "Dangerous":
            st.error("Dangerous")
        elif res.get("verdict") == "Suspicious":
            st.warning("Suspicious")
        else:
            st.success("Safe")
        st.subheader("Overall")
        if res.get("verdict") == "Safe":
            st.success("Safe")
        else:
            st.error("Not Safe")
        st.subheader("Sender")
        st.json({"sender": res.get("sender"), "sender_domain": res.get("sender_domain")})
        st.subheader("Links Found")
        for l in res.get("links", []):
            st.write(f"- {l}")
        st.subheader("Reasons")
        for r in res.get("reasons", []):
            st.write(f"- {r}")

st.markdown(
    """
    <style>
    .custom-footer { position: fixed; bottom: 8px; left: 0; right: 0; text-align: center; z-index: 9999; }
    .custom-footer span { font-family: 'Brush Script MT', cursive; font-size: 18px; }
    .custom-footer a { font-family: 'Brush Script MT', cursive; font-size: 18px; color: #1f6feb; text-decoration: underline; }
    </style>
    <div class="custom-footer">
      <span>Made by </span><a href="https://visionkc.com.np" target="_blank" rel="noopener noreferrer">Vision</a>
    </div>
    """,
    unsafe_allow_html=True,
)
