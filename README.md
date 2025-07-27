# 🧠 PronouncePal Backend – Django + TensorFlow

This is the backend system powering the PronouncePal app — a speech improvement tool designed for children learning **Urdu pronunciation**. It uses a **TensorFlow-based model** for speech recognition and pronunciation scoring, served via a secure and scalable **Django REST API**.

---

## 🏗️ Tech Stack

- ⚙️ Django + Django REST Framework
- 🧠 TensorFlow (pre-trained speech model)
- 📦 SQLite (default) or PostgreSQL
- 📁 Dataset and trained model stored in root folders

---

> 📝 **Note:** App dataset and model files are included in the [`dataset/`](./Word_Dataset) and [`model/`](./Pronunounce_model(2).h5) folders respectively.

---

## 🚀 Getting Started (All Commands)

### 🔧 1. Clone the Repository

```bash
git clone https://github.com/your-username/pronouncepal-backend.git
cd pronouncepal-backend
python -m venv venv
source venv/bin/activate         # Linux/macOS
venv\Scripts\activate            # Windows
python manage.py migrate
python manage.py runserver

