# 🔍 HTTP Interceptor Proxy

A powerful and lightweight HTTP interceptor written in Python. This tool acts as a proxy server, allowing you to **capture**, **inspect**, **modify**, **block**, and **forge** HTTP GET and POST requests in real-time.

---

## ⚙️ Features

- ✅ Intercepts all HTTP GET and POST requests
- 🔍 Real-time request and response logging
- ✏️ Modify headers, body, or URL on the fly
- 🚫 Block specific URLs or patterns
- 🧪 Forge custom requests manually
- 🌐 Web-based interface for viewing and managing traffic
- 🧰 Minimal dependencies and easy to deploy

---
🔧 Prerequisites
Ensure you have the following installed:

    Node.js (if you're using a JS backend)

    Python (if you're using a Python backend)

    Forge (Laravel project users)

    A web browser (Chrome or Firefox)

    FoxyProxy Extension (for managing proxies)

🦊 Using FoxyProxy (Browser Setup)
Install the FoxyProxy extension:

    Firefox

    Chrome

Configure a Proxy:

    Click the FoxyProxy icon and go to Options.

Add a New Proxy:

    Enter the Host/IP and Port.

    (Optional) Add authentication if required.

    Under URL Patterns, specify domains to apply the proxy to.

    Save and enable the proxy profile.

⚙️ Project Configuration
1. Clone the Repository
    bash
    Copy
    Edit
    git clone https://github.com/your-username/your-project.git
    cd your-project

2. Install Dependencies
For a Node.js project:
    bash
    Copy
    Edit
    npm install
For a Python project:
    bash
    Copy
    Edit
    pip install -r requirements.txt
For a Laravel project:
    bash
    Copy
    Edit
    composer install

3. Set Up Environment Variables
Create a .env file:
    env
    Copy
    Edit
    PORT=5000
    PROXY_PORT=8080
    API_KEY=your_api_key

# ... other variables
For Laravel, copy .env.example:
    bash
    Copy
    Edit
    cp .env.example .env
    php artisan key:generate
🔨 Running the Application
With Node.js:
    bash
    Copy
    Edit
    npm start
# OR
    node index.js
    With Python (Flask/Django):
    bash
    Copy
    Edit
    python app.py
# OR for Django
python manage.py runserver
With Laravel (Forge/Artisan):
    bash
    Copy
    Edit
    php artisan serve
# OR deploy via Forge
🌐 Accessing the Application
Visit your app at:
    arduino
    Copy
    Edit
    http://localhost:5000

If using a proxy:
    php-template
    Copy
    Edit
    http://<proxy-ip>:<proxy-port>
🧪 Testing the Proxy
Open your browser and enable FoxyProxy.

Navigate to your app.

Visit whatismyip.com to verify IP change.

Ensure your requests are routed via the proxy.

📄 Additional Notes
If you run into CORS issues, make sure the server supports proper headers.

Restart your server after any .env changes.

Adjust firewall or antivirus if your proxy is blocked.