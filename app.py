import hashlib
import hmac
import logging
import os
import re
import secrets
import smtplib
import sqlite3
import ssl
import time
from contextlib import closing
from datetime import date, datetime, timedelta, timezone
from email.message import EmailMessage
from functools import wraps

from flask import Flask, g, jsonify, render_template, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.config['ENVIRONMENT'] = os.environ.get('MEDCONNECT_ENV', 'development').strip().lower()
configured_secret = os.environ.get('MEDCONNECT_SECRET_KEY')
if app.config['ENVIRONMENT'] == 'production' and not configured_secret:
    raise RuntimeError('MEDCONNECT_SECRET_KEY must be configured in production.')
if app.config['ENVIRONMENT'] == 'production' and len(configured_secret) < 32:
    raise RuntimeError('MEDCONNECT_SECRET_KEY must contain at least 32 characters.')
app.secret_key = configured_secret or os.urandom(32)
app.config['DATABASE'] = os.environ.get(
    'MEDCONNECT_DATABASE',
    os.path.join(app.root_path, 'medconnect.db'),
)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = (
    app.config['ENVIRONMENT'] == 'production'
    or os.environ.get('MEDCONNECT_COOKIE_SECURE', '').strip().lower() == 'true'
)
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=12)
app.config['MAX_CONTENT_LENGTH'] = 64 * 1024
if os.environ.get('MEDCONNECT_TRUSTED_PROXY', '').strip().lower() == 'true':
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1)
logger = logging.getLogger(__name__)


@app.after_request
def set_security_headers(response):
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'DENY')
    response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    response.headers.setdefault('Permissions-Policy', 'camera=(), geolocation=(), microphone=(self)')
    if app.config['SESSION_COOKIE_SECURE']:
        response.headers.setdefault(
            'Strict-Transport-Security', 'max-age=31536000; includeSubDomains'
        )
    return response

HEALTH_TIPS = (
    (
        (
            "zukham", "jhukam", "jhukham", "sardi", "जुकाम", "सर्दी", "बुखार",
            "cold", "bukhar", "fever", "paracetamol", "steam", "bhaap",
            "खांसी", "khansi", "cough", "naak band",
        ),
        """For a cold, cough, or fever:
• Drink fluids and rest. Saline spray or drops may help a blocked nose.
• If steam feels soothing, sit in a steamy bathroom; do not inhale steam over boiling water because it can cause burns.
• For fever or pain, take paracetamol only as directed on its label. Check other cold/flu medicines for paracetamol to avoid taking too much.
• Do not give honey to a child under 1 year. Antibiotics do not treat viral colds; do not take them without medical advice.""",
        """सर्दी, खाँसी या बुखार में:
• पर्याप्त तरल पिएँ और आराम करें। नाक बंद हो तो सलाइन स्प्रे या ड्रॉप्स से मदद मिल सकती है।
• भाप से आराम मिले तो गरम शॉवर वाले बाथरूम में बैठें। उबलते पानी के ऊपर सीधे भाप न लें—जलने का खतरा है।
• बुखार या दर्द में पैरासिटामोल केवल पैकेट पर लिखे निर्देश के अनुसार लें। दूसरी सर्दी-जुकाम की दवाओं में भी पैरासिटामोल हो सकता है, इसलिए अधिक मात्रा से बचें।
• एक साल से छोटे बच्चे को शहद न दें। वायरल सर्दी में एंटीबायोटिक काम नहीं करती; डॉक्टर की सलाह के बिना न लें।"""
    ),
    (
        (
            "gale mein dard", "gala dard", "गले में दर्द", "sore throat", "throat pain",
            "gale ki kharash", "galey mein dard", "nigalne mein dard",
        ),
        """For a sore throat:
• Gargle with warm salt water and spit it out (do not ask young children to gargle). Drink fluids and rest.
• Paracetamol may help with pain when taken according to the label. Ask a pharmacist about lozenges or other medicines. Do not take antibiotics on your own.
• Contact a doctor for difficulty breathing or swallowing, a high fever, or a sore throat that is not improving after a week.""",
        """गले में दर्द होने पर:
• गरम नमक-पानी से गरारे करके उसे थूक दें (छोटे बच्चों को गरारे न कराएँ)। तरल पिएँ और आराम करें।
• दर्द में पैकेट के निर्देशानुसार पैरासिटामोल मदद कर सकती है। लोज़ेंज या दूसरी दवा के लिए फार्मासिस्ट से पूछें। अपनी मर्ज़ी से एंटीबायोटिक न लें।
• साँस लेने या निगलने में परेशानी, तेज़ बुखार, या एक हफ्ते में सुधार न होने पर डॉक्टर से संपर्क करें।"""
    ),
    (
        (
            "loose motion", "loose motions", "diarrhea", "diarrhoea", "dast", "दस्त",
            "pet kharab", "watery stool",
        ),
        """For diarrhoea:
• Drink fluids and use oral rehydration solution (ORS). Mix an ORS packet with exactly the amount of clean water stated on its label.
• Seek urgent medical help for blood in stool, very little urine, fainting or unusual drowsiness, inability to keep fluids down, or signs of dehydration.
• Do not take antibiotics or anti-diarrhoea medicines without advice from a doctor or pharmacist.""",
        """दस्त होने पर:
• तरल पदार्थ और ओआरएस लें। ओआरएस का पैकेट उतने ही साफ़ पानी में घोलें जितना पैकेट पर लिखा है।
• मल में खून, बहुत कम पेशाब, बेहोशी या असामान्य सुस्ती, तरल न रुकना, या शरीर में पानी की कमी के लक्षण हों तो तुरंत चिकित्सा सहायता लें।
• डॉक्टर या फार्मासिस्ट की सलाह के बिना एंटीबायोटिक या दस्त रोकने की दवा न लें।"""
    ),
    (
        ("kabz", "constipation", "कब्ज", "hard stool", "motion nahi"),
        """For constipation:
• Gradually add fibre-rich fruit and vegetables, drink water, take a gentle daily walk, and do not ignore the urge to use the toilet.
• If this does not help, ask a pharmacist whether a suitable laxative is appropriate. Do not use one long-term without advice.
• Contact a doctor for severe abdominal pain, blood in stool, unexplained weight loss, or recurring constipation.""",
        """कब्ज़ होने पर:
• धीरे-धीरे फाइबर वाले फल और सब्ज़ियाँ बढ़ाएँ, पानी पिएँ, रोज़ हल्की सैर करें और शौच की इच्छा को न रोकें।
• आराम न मिले तो फार्मासिस्ट से पूछें कि कौन-सी जुलाब की दवा उचित है। बिना सलाह इसे लंबे समय तक न लें।
• तेज़ पेट-दर्द, मल में खून, बिना कारण वज़न घटना, या बार-बार कब्ज़ होने पर डॉक्टर से संपर्क करें।"""
    ),
    (
        (
            "acidity", "heartburn", "acid reflux", "khatti dakar", "seene mein jalan",
            "pet mein jalan", "indigestion",
        ),
        """For occasional heartburn:
• Try smaller meals, avoid foods that trigger your symptoms, and do not eat within 3–4 hours of bedtime.
• An antacid or alginate may provide short-term relief. Ask a pharmacist and follow the label.
• Get urgent medical help for severe chest pain, breathing difficulty, vomiting blood, or difficulty swallowing.""",
        """कभी-कभी होने वाली सीने की जलन में:
• थोड़ा-थोड़ा खाएँ, जिन चीज़ों से परेशानी बढ़ती है उनसे बचें, और सोने से 3–4 घंटे पहले खाना न खाएँ।
• एंटासिड या एल्जिनेट से थोड़े समय के लिए आराम मिल सकता है। फार्मासिस्ट से पूछें और पैकेट के निर्देश मानें।
• तेज़ सीने का दर्द, साँस लेने में परेशानी, खून की उल्टी, या निगलने में कठिनाई हो तो तुरंत चिकित्सा सहायता लें।"""
    ),
    (
        ("sar dard", "sir dard", "headache", "head pain", "सिरदर्द", "सिर दर्द"),
        """For a mild headache, drink water, rest, and take a break from screens. If needed, take paracetamol only as directed on its label; check other medicines to avoid taking it twice.
• Get emergency medical help for a sudden severe headache, a headache after an injury, weakness or confusion, or problems with vision or speech.""",
        """हल्का सिरदर्द हो तो पानी पिएँ, आराम करें और स्क्रीन से थोड़ा विराम लें। ज़रूरत पड़ने पर पैरासिटामोल केवल पैकेट के निर्देशानुसार लें; दूसरी दवाओं में भी यह हो सकती है, इसलिए दोहरी खुराक से बचें।
• अचानक बहुत तेज़ सिरदर्द, चोट के बाद सिरदर्द, कमज़ोरी या भ्रम, या देखने-बोलने में परेशानी हो तो आपातकालीन चिकित्सा सहायता लें।"""
    ),
    (
        (
            "allergy", "allergies", "allergic", "hay fever", "एलर्जी", "allergy rash",
            "छींक", "sneezing", "itchy eyes", "आँखों में खुजली",
        ),
        """For mild allergy symptoms, avoid the trigger if you know it and wash exposed skin. A pharmacist can advise whether an antihistamine is suitable.
• Get emergency help for trouble breathing or swelling of the tongue or throat. Seek medical advice for a severe, spreading, or persistent rash.""",
        """हल्की एलर्जी में, कारण पता हो तो उससे बचें और प्रभावित त्वचा धो लें। एंटीहिस्टामिन उपयुक्त है या नहीं, इसके लिए फार्मासिस्ट से पूछें।
• साँस लेने में परेशानी या जीभ/गले में सूजन हो तो तुरंत आपातकालीन सहायता लें। तेज़ी से फैलते या ठीक न होने वाले चकत्ते पर डॉक्टर से सलाह लें।"""
    ),
)

MEDICINE_INFO = (
    (
        ("paracetamol", "acetaminophen", "crocin", "dolo", "पैरासिटामोल", "पेरासिटामोल"),
        """Paracetamol (acetaminophen) is used for pain or fever. Follow the product label and check cold/flu products so you do not take it twice. Ask a clinician or pharmacist first if you have liver disease or drink heavily.""",
        """पैरासिटामोल (एसीटामिनोफेन) दर्द या बुखार में इस्तेमाल होती है। पैकेट के निर्देश मानें और सर्दी-जुकाम की दूसरी दवाओं में भी इसे जाँचें, ताकि दोहरी मात्रा न हो। लिवर की बीमारी या अधिक शराब के सेवन में पहले डॉक्टर/फार्मासिस्ट से पूछें।"""
    ),
    (
        ("ibuprofen", "brufen", "इबुप्रोफेन"),
        """Ibuprofen can help with pain, inflammation, or fever, but may irritate the stomach and affect the kidneys. Ask a clinician or pharmacist before use if you have stomach ulcers, kidney disease, dehydration, take blood thinners, or are pregnant; do not combine it with similar painkillers unless advised.""",
        """इबुप्रोफेन दर्द, सूजन या बुखार में मदद कर सकती है, लेकिन पेट में जलन/घाव और किडनी पर असर का जोखिम हो सकता है। पेट के अल्सर, किडनी की बीमारी, शरीर में पानी की कमी, खून पतला करने वाली दवा लेने या गर्भावस्था में पहले डॉक्टर/फार्मासिस्ट से पूछें। सलाह के बिना इसे इसी तरह की दूसरी दर्द की दवाओं के साथ न लें।"""
    ),
    (
        ("cetirizine", "cetrizine", "zyrtec", "सेटिरिज़िन", "सेटिरिजिन"),
        """Cetirizine is an antihistamine used for allergy symptoms. It can cause sleepiness; check the label and avoid driving or alcohol if drowsy. Ask a pharmacist whether it is suitable for a child or if you have kidney disease or take other sedating medicines.""",
        """सेटिरिज़िन एलर्जी के लक्षणों में इस्तेमाल होने वाली एंटीहिस्टामिन है। इससे नींद आ सकती है; पैकेट के निर्देश पढ़ें और नींद आने पर गाड़ी चलाने या शराब से बचें। बच्चे, किडनी की बीमारी, या नींद लाने वाली दूसरी दवाओं के मामले में फार्मासिस्ट से पूछें।"""
    ),
    (
        ("ors", "oral rehydration salts", "oral rehydration solution", "ओआरएस"),
        """ORS helps replace fluid and salts lost through diarrhoea. Mix a packet with exactly the amount of clean water printed on it; do not make it stronger or weaker. Seek urgent care for very little urine, unusual drowsiness, blood in stool, or inability to keep fluids down.""",
        """ओआरएस दस्त में शरीर से निकले पानी और लवण की कमी पूरी करने में मदद करता है। पैकेट पर लिखी साफ़ पानी की ठीक मात्रा में ही घोलें; घोल को गाढ़ा या पतला न बनाएँ। बहुत कम पेशाब, असामान्य सुस्ती, मल में खून, या तरल न रुकने पर तुरंत चिकित्सा सहायता लें।"""
    ),
    (
        ("antacid", "antacids", "एंटासिड", "alginate"),
        """Antacids or alginates may give short-term relief from occasional heartburn. Follow the label and ask a pharmacist if you have kidney disease or take other medicines, as antacids can affect how some medicines are absorbed. Frequent heartburn needs medical advice.""",
        """एंटासिड या एल्जिनेट कभी-कभी होने वाली सीने की जलन में थोड़े समय के लिए राहत दे सकते हैं। पैकेट के निर्देश मानें। किडनी की बीमारी या दूसरी दवाएँ लेने पर फार्मासिस्ट से पूछें, क्योंकि एंटासिड कुछ दवाओं के असर/अवशोषण को बदल सकते हैं। बार-बार जलन हो तो डॉक्टर से सलाह लें।"""
    ),
    (
        (
            "omeprazole", "pantoprazole", "ओमेप्राज़ोल", "ओमेप्राजोल",
            "पैंटोप्राज़ोल", "पैंटोप्राजोल",
        ),
        """Omeprazole and pantoprazole reduce stomach acid and are used for some acid-related conditions; they are not quick-relief medicines for every kind of chest or stomach pain. Use them only as directed by a clinician or the product label, and ask a pharmacist about other medicines you take.""",
        """ओमेप्राज़ोल और पैंटोप्राज़ोल पेट का एसिड कम करती हैं और कुछ एसिड-संबंधी समस्याओं में इस्तेमाल होती हैं; ये हर तरह के सीने या पेट के दर्द में तुरंत राहत की दवा नहीं हैं। डॉक्टर या पैकेट के निर्देशानुसार ही लें और दूसरी दवाओं के बारे में फार्मासिस्ट से पूछें।"""
    ),
    (
        (
            "antibiotic", "antibiotics", "amoxicillin", "azithromycin",
            "एंटीबायोटिक", "एंटीबायोटिक्स", "एंटीबायोटिक दवा",
        ),
        """Antibiotics treat some bacterial infections, not viral colds or flu. They need a clinician's assessment and prescription; do not use leftover antibiotics or someone else's medicine. Ask a pharmacist or clinician about allergies or side effects.""",
        """एंटीबायोटिक कुछ बैक्टीरियल संक्रमणों में काम करती हैं, वायरल सर्दी-जुकाम या फ्लू में नहीं। इनके लिए डॉक्टर की जाँच और पर्चा ज़रूरी है; बची हुई या किसी और की दवा न लें। एलर्जी या दुष्प्रभाव के बारे में डॉक्टर/फार्मासिस्ट से पूछें।"""
    ),
)


def utc_now():
    return datetime.now(timezone.utc)


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(app.config['DATABASE'], timeout=30)
        g.db.row_factory = sqlite3.Row
        g.db.execute('PRAGMA foreign_keys = ON')
        g.db.execute('PRAGMA busy_timeout = 30000')
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    database = g.pop('db', None)
    if database is not None:
        database.close()


def initialize_db():
    os.makedirs(os.path.dirname(os.path.abspath(app.config['DATABASE'])), exist_ok=True)
    with closing(sqlite3.connect(app.config['DATABASE'], timeout=30)) as database:
        with database:
            database.execute('PRAGMA journal_mode = WAL')
            database.execute('PRAGMA foreign_keys = ON')
            database.executescript(
                '''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    policy_accepted_at TEXT
                );
                CREATE TABLE IF NOT EXISTS medications (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL REFERENCES users(id),
                    name TEXT NOT NULL,
                    schedule_time TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS dose_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL REFERENCES users(id),
                    medication_id INTEGER NOT NULL,
                    medication_name TEXT NOT NULL,
                    schedule_time TEXT NOT NULL,
                    taken_at TEXT NOT NULL,
                    taken_date TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS password_reset_codes (
                    email TEXT PRIMARY KEY,
                    user_id INTEGER,
                    otp_hash TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    request_ip TEXT NOT NULL,
                    window_started_at TEXT NOT NULL,
                    requests_in_window INTEGER NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS rate_limit_counters (
                    scope TEXT NOT NULL,
                    client_hash TEXT NOT NULL,
                    window_start INTEGER NOT NULL,
                    request_count INTEGER NOT NULL,
                    PRIMARY KEY (scope, client_hash, window_start)
                );
                '''
            )
            user_columns = {
                row[1] for row in database.execute('PRAGMA table_info(users)')
            }
            if 'policy_accepted_at' not in user_columns:
                database.execute('ALTER TABLE users ADD COLUMN policy_accepted_at TEXT')
            database.execute(
                "UPDATE password_reset_codes SET request_ip = '' WHERE request_ip != ''"
            )
            columns = {
                row[1] for row in database.execute('PRAGMA table_info(dose_history)')
            }
            if 'status' not in columns:
                database.execute(
                    "ALTER TABLE dose_history ADD COLUMN status TEXT NOT NULL DEFAULT 'taken'"
                )
            database.execute(
                'CREATE INDEX IF NOT EXISTS idx_dose_history_user_date '
                'ON dose_history(user_id, taken_date)'
            )


def request_data():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return None, (jsonify({'error': 'Request JSON format sahi nahi hai.'}), 400)
    return data, None


def rate_limited(scope, limit, window_seconds):
    def decorate(handler):
        @wraps(handler)
        def wrapped(*args, **kwargs):
            now = int(time.time())
            window_start = now - now % window_seconds
            client_hash = client_address_digest(scope)
            database = get_db()
            database.execute(
                'DELETE FROM rate_limit_counters WHERE scope = ? AND window_start < ?',
                (scope, window_start),
            )
            database.execute(
                '''
                INSERT INTO rate_limit_counters(scope, client_hash, window_start, request_count)
                VALUES (?, ?, ?, 1)
                ON CONFLICT(scope, client_hash, window_start)
                DO UPDATE SET request_count = request_count + 1
                ''',
                (scope, client_hash, window_start),
            )
            request_count = database.execute(
                '''
                SELECT request_count FROM rate_limit_counters
                WHERE scope = ? AND client_hash = ? AND window_start = ?
                ''',
                (scope, client_hash, window_start),
            ).fetchone()['request_count']
            database.commit()
            if request_count > limit:
                retry_after = window_start + window_seconds - now
                response = jsonify({'error': 'Bahut saari requests hui hain. Thodi der baad dobara koshish karein.'})
                response.status_code = 429
                response.headers['Retry-After'] = str(max(1, retry_after))
                return response
            return handler(*args, **kwargs)

        return wrapped

    return decorate


def client_address_digest(scope):
    remote_address = request.remote_addr or 'unknown'
    secret = app.secret_key.encode() if isinstance(app.secret_key, str) else app.secret_key
    return hmac.new(
        secret,
        f'{scope}\0{remote_address}'.encode(),
        hashlib.sha256,
    ).hexdigest()


def current_user():
    user_id = session.get('user_id')
    if not user_id:
        return None
    return get_db().execute(
        'SELECT id, name, email FROM users WHERE id = ?', (user_id,)
    ).fetchone()


def login_required(handler):
    @wraps(handler)
    def wrapped(*args, **kwargs):
        if not current_user():
            return jsonify({'error': 'Pehle login karein.'}), 401
        return handler(*args, **kwargs)

    return wrapped


def user_payload(user):
    return {'id': user['id'], 'name': user['name'], 'email': user['email']}


def valid_email(value):
    return isinstance(value, str) and len(value) <= 254 and re.fullmatch(
        r'[^@\s]+@[^@\s]+\.[^@\s]+', value
    )


def valid_time(value):
    if not isinstance(value, str) or not re.fullmatch(r'(?:[01]\d|2[0-3]):[0-5]\d', value):
        return False
    return True


def valid_date(value):
    if not isinstance(value, str):
        return False
    try:
        return date.fromisoformat(value).isoformat() == value
    except ValueError:
        return False


def otp_digest(otp):
    secret = app.secret_key.encode() if isinstance(app.secret_key, str) else app.secret_key
    return hmac.new(secret, otp.encode(), hashlib.sha256).hexdigest()


def send_password_reset_email(email, otp):
    sender = os.environ.get('MEDCONNECT_GMAIL_ADDRESS', '').strip()
    app_password = os.environ.get('MEDCONNECT_GMAIL_APP_PASSWORD', '').replace(' ', '')
    if not sender.casefold().endswith('@gmail.com') or not app_password:
        raise RuntimeError(
            'Password reset email ke liye MEDCONNECT_GMAIL_ADDRESS aur '
            'MEDCONNECT_GMAIL_APP_PASSWORD configure karein.'
        )

    message = EmailMessage()
    message['Subject'] = 'MedConnect password reset OTP'
    message['From'] = sender
    message['To'] = email
    message.set_content(
        f'MedConnect password reset OTP: {otp}\n\n'
        'Yeh code 10 minute mein expire ho jayega. Is code ko kisi ke saath share na karein.'
    )
    with smtplib.SMTP('smtp.gmail.com', 587, timeout=15) as smtp:
        smtp.starttls(context=ssl.create_default_context())
        smtp.login(sender, app_password)
        smtp.send_message(message)


@app.get('/')
def home():
    return send_from_directory(app.root_path, '1index.html')


@app.get('/privacy')
def privacy_policy():
    return render_template(
        'privacy.html',
        support_email=os.environ.get('MEDCONNECT_SUPPORT_EMAIL', ''),
    )


@app.get('/terms')
def terms_of_use():
    return render_template(
        'terms.html',
        support_email=os.environ.get('MEDCONNECT_SUPPORT_EMAIL', ''),
    )


@app.get('/healthz')
def health_check():
    get_db().execute('SELECT 1').fetchone()
    return jsonify({'status': 'ok'})


@app.get('/api/session')
def session_status():
    user = current_user()
    return jsonify({'user': user_payload(user) if user else None})


@app.post('/api/signup')
@rate_limited('signup', 5, 3600)
def signup():
    data, error = request_data()
    if error:
        return error

    name = data.get('name', '').strip() if isinstance(data.get('name'), str) else ''
    email_value = data.get('email')
    email = email_value.strip().casefold() if isinstance(email_value, str) else ''
    password = data.get('password', '')
    if not name or len(name) > 100 or not valid_email(email):
        return jsonify({'error': 'Sahi naam aur email address bharein.'}), 400
    if not isinstance(password, str) or len(password) < 8 or len(password) > 256:
        return jsonify({'error': 'Password kam se kam 8 characters ka hona chahiye.'}), 400
    if data.get('policy_accepted') is not True:
        return jsonify({'error': 'Sign up karne ke liye privacy policy aur terms se sahmat hona zaroori hai.'}), 400

    database = get_db()
    try:
        cursor = database.execute(
            'INSERT INTO users(name, email, password_hash, policy_accepted_at) VALUES (?, ?, ?, ?)',
            (name, email, generate_password_hash(password), utc_now().isoformat()),
        )
        database.commit()
    except sqlite3.IntegrityError:
        database.rollback()
        return jsonify({'error': 'Is email se account pehle se bana hua hai.'}), 409

    session.clear()
    session['user_id'] = cursor.lastrowid
    session.permanent = True
    return jsonify({'user': {'id': cursor.lastrowid, 'name': name, 'email': email}}), 201


@app.post('/api/login')
@rate_limited('login', 10, 900)
def login():
    data, error = request_data()
    if error:
        return error
    email = data.get('email', '').strip().casefold() if isinstance(data.get('email'), str) else ''
    password = data.get('password', '')
    user = get_db().execute(
        'SELECT id, name, email, password_hash FROM users WHERE email = ?', (email,)
    ).fetchone()
    if not user or not isinstance(password, str) or not check_password_hash(
        user['password_hash'], password
    ):
        return jsonify({'error': 'Email ya password sahi nahi hai.'}), 401

    session.clear()
    session['user_id'] = user['id']
    session.permanent = True
    return jsonify({'user': user_payload(user)})


@app.post('/api/logout')
def logout():
    session.clear()
    return jsonify({'ok': True})


@app.post('/api/account/delete')
@rate_limited('account-delete', 5, 900)
@login_required
def delete_account():
    data, error = request_data()
    if error:
        return error

    password = data.get('password')
    if not isinstance(password, str) or not password or len(password) > 256:
        return jsonify({'error': 'Account delete karne ke liye current password bharein.'}), 400

    database = get_db()
    user_id = session['user_id']
    user = database.execute(
        'SELECT email, password_hash FROM users WHERE id = ?', (user_id,)
    ).fetchone()
    if not user or not check_password_hash(user['password_hash'], password):
        return jsonify({'error': 'Password sahi nahi hai; account delete nahi hua.'}), 403

    database.execute('BEGIN IMMEDIATE')
    database.execute('DELETE FROM dose_history WHERE user_id = ?', (user_id,))
    database.execute('DELETE FROM medications WHERE user_id = ?', (user_id,))
    database.execute(
        'DELETE FROM password_reset_codes WHERE user_id = ? OR email = ?',
        (user_id, user['email']),
    )
    database.execute('DELETE FROM users WHERE id = ?', (user_id,))
    database.commit()
    session.clear()
    return jsonify({'ok': True})


@app.post('/api/password-reset/request')
@rate_limited('password-reset-request', 5, 900)
def request_password_reset():
    data, error = request_data()
    if error:
        return error
    email = data.get('email', '').strip().casefold() if isinstance(data.get('email'), str) else ''
    if not valid_email(email) or not email.endswith('@gmail.com'):
        return jsonify({'error': 'Sahi Gmail address bharein.'}), 400

    database = get_db()
    database.execute(
        'DELETE FROM password_reset_codes WHERE expires_at < ?',
        (utc_now().isoformat(),),
    )
    user = database.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
    if not user:
        return jsonify({'message': 'Agar account registered hai, reset instructions email kiye jayenge.'})

    now = utc_now()
    existing = database.execute(
        'SELECT window_started_at, requests_in_window FROM password_reset_codes WHERE email = ?',
        (email,),
    ).fetchone()
    window_start = now - timedelta(minutes=15)
    if existing:
        try:
            prior_start = datetime.fromisoformat(existing['window_started_at'])
        except ValueError:
            prior_start = window_start
        if prior_start.tzinfo is None:
            prior_start = prior_start.replace(tzinfo=timezone.utc)
        if prior_start > window_start and existing['requests_in_window'] >= 5:
            return jsonify({'error': 'Bahut saare OTP requests hue hain. 15 minute baad dobara koshish karein.'}), 429
        request_count = existing['requests_in_window'] + 1 if prior_start > window_start else 1
        recorded_window = prior_start if prior_start > window_start else now
    else:
        request_count = 1
        recorded_window = now

    otp = f'{secrets.randbelow(1_000_000):06d}'
    try:
        send_password_reset_email(email, otp)
    except (OSError, RuntimeError, smtplib.SMTPException) as exc:
        logger.exception('Could not send password reset email')
        return jsonify({'error': str(exc)}), 503

    database.execute(
        '''
        INSERT INTO password_reset_codes(
            email, user_id, otp_hash, created_at, expires_at, request_ip,
            window_started_at, requests_in_window, attempts
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
        ON CONFLICT(email) DO UPDATE SET
            user_id=excluded.user_id,
            otp_hash=excluded.otp_hash,
            created_at=excluded.created_at,
            expires_at=excluded.expires_at,
            request_ip=excluded.request_ip,
            window_started_at=excluded.window_started_at,
            requests_in_window=excluded.requests_in_window,
            attempts=0
        ''',
        (
            email, user['id'], otp_digest(otp), now.isoformat(),
            (now + timedelta(minutes=10)).isoformat(),
            client_address_digest('password-reset-request'),
            recorded_window.isoformat(), request_count,
        ),
    )
    database.commit()
    return jsonify({'message': 'Aapke Gmail par 10 minute ke liye valid OTP bheja gaya hai.'})


@app.post('/api/password-reset/confirm')
@rate_limited('password-reset-confirm', 10, 900)
def confirm_password_reset():
    data, error = request_data()
    if error:
        return error
    email = data.get('email', '').strip().casefold() if isinstance(data.get('email'), str) else ''
    otp = data.get('otp', '')
    password = data.get('password', '')
    if not valid_email(email) or not isinstance(otp, str) or not re.fullmatch(r'\d{6}', otp):
        return jsonify({'error': 'Gmail aur 6-digit OTP sahi bharein.'}), 400
    if not isinstance(password, str) or len(password) < 8 or len(password) > 256:
        return jsonify({'error': 'Naya password kam se kam 8 characters ka hona chahiye.'}), 400

    database = get_db()
    reset = database.execute(
        'SELECT user_id, otp_hash, expires_at, attempts FROM password_reset_codes WHERE email = ?',
        (email,),
    ).fetchone()
    if not reset or reset['attempts'] >= 5:
        return jsonify({'error': 'OTP valid nahi hai ya expire ho gaya. Naya OTP mangwayein.'}), 400

    try:
        expires_at = datetime.fromisoformat(reset['expires_at'])
    except ValueError:
        expires_at = datetime.min.replace(tzinfo=timezone.utc)
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at <= utc_now():
        database.execute('DELETE FROM password_reset_codes WHERE email = ?', (email,))
        database.commit()
        return jsonify({'error': 'OTP expire ho gaya. Naya OTP mangwayein.'}), 400

    if not hmac.compare_digest(reset['otp_hash'], otp_digest(otp)):
        database.execute(
            'UPDATE password_reset_codes SET attempts = attempts + 1 WHERE email = ?',
            (email,),
        )
        database.commit()
        return jsonify({'error': 'OTP sahi nahi hai.'}), 400

    database.execute(
        'UPDATE users SET password_hash = ? WHERE id = ?',
        (generate_password_hash(password), reset['user_id']),
    )
    database.execute('DELETE FROM password_reset_codes WHERE email = ?', (email,))
    database.commit()
    return jsonify({'message': 'Password successfully badal diya gaya.'})


@app.get('/api/medications')
@login_required
def list_medications():
    today = date.today().isoformat()
    rows = get_db().execute(
        '''
        SELECT m.id, m.name, m.schedule_time,
               COALESCE(h.status, '') = 'taken' AS taken_today
        FROM medications AS m
        LEFT JOIN dose_history AS h
          ON h.medication_id = m.id AND h.user_id = m.user_id AND h.taken_date = ?
        WHERE m.user_id = ?
        ORDER BY m.schedule_time, m.id
        ''',
        (today, session['user_id']),
    ).fetchall()
    return jsonify({'medications': [
        {
            'id': row['id'],
            'name': row['name'],
            'schedule_time': row['schedule_time'],
            'taken_today': bool(row['taken_today']),
        }
        for row in rows
    ]})


@app.post('/api/medications')
@login_required
def add_medication():
    data, error = request_data()
    if error:
        return error
    name = data.get('name', '').strip() if isinstance(data.get('name'), str) else ''
    schedule_time = data.get('time', '')
    if not name or len(name) > 120 or not valid_time(schedule_time):
        return jsonify({'error': 'Dawa ka naam aur sahi samay bharein.'}), 400

    database = get_db()
    cursor = database.execute(
        'INSERT INTO medications(user_id, name, schedule_time, created_at) VALUES (?, ?, ?, ?)',
        (session['user_id'], name, schedule_time, utc_now().isoformat()),
    )
    database.commit()
    return jsonify({
        'medication': {
            'id': cursor.lastrowid,
            'name': name,
            'schedule_time': schedule_time,
            'taken_today': False,
        }
    }), 201


def get_medication_for_user(database, medication_id):
    return database.execute(
        'SELECT id, name, schedule_time FROM medications WHERE id = ? AND user_id = ?',
        (medication_id, session['user_id']),
    ).fetchone()


@app.post('/api/medications/<int:medication_id>/taken')
@login_required
def mark_medication_taken(medication_id):
    data, error = request_data()
    if error:
        return error
    taken_date = data.get('date', date.today().isoformat())
    if not valid_date(taken_date):
        return jsonify({'error': 'Dose ki date sahi format mein nahi hai.'}), 400

    database = get_db()
    medication = get_medication_for_user(database, medication_id)
    if not medication:
        return jsonify({'error': 'Yeh dawa nahi mili.'}), 404

    timestamp = utc_now().isoformat(timespec='seconds')
    database.execute('BEGIN IMMEDIATE')
    existing = database.execute(
        'SELECT id FROM dose_history WHERE user_id = ? AND medication_id = ? AND taken_date = ?',
        (session['user_id'], medication_id, taken_date),
    ).fetchone()
    if existing:
        database.execute(
            '''
            UPDATE dose_history
            SET medication_name = ?, schedule_time = ?, taken_at = ?, status = 'taken'
            WHERE id = ?
            ''',
            (medication['name'], medication['schedule_time'], timestamp, existing['id']),
        )
    else:
        database.execute(
            '''
            INSERT INTO dose_history(
                user_id, medication_id, medication_name, schedule_time, taken_at, taken_date, status
            ) VALUES (?, ?, ?, ?, ?, ?, 'taken')
            ''',
            (
                session['user_id'], medication_id, medication['name'],
                medication['schedule_time'], timestamp, taken_date,
            ),
        )
    database.commit()
    return jsonify({'ok': True})


@app.post('/api/medications/<int:medication_id>/missed')
@login_required
def mark_medication_missed(medication_id):
    data, error = request_data()
    if error:
        return error
    missed_date = data.get('date', '')
    if not valid_date(missed_date):
        return jsonify({'error': 'Dose ki date sahi format mein nahi hai.'}), 400

    database = get_db()
    medication = get_medication_for_user(database, medication_id)
    if not medication:
        return jsonify({'error': 'Yeh dawa nahi mili.'}), 404

    database.execute('BEGIN IMMEDIATE')
    existing = database.execute(
        'SELECT id, status FROM dose_history WHERE user_id = ? AND medication_id = ? AND taken_date = ?',
        (session['user_id'], medication_id, missed_date),
    ).fetchone()
    if existing and existing['status'] == 'taken':
        database.commit()
        return jsonify({'ok': True, 'status': 'taken'})
    if existing:
        database.commit()
        return jsonify({'ok': True, 'status': 'missed'})

    database.execute(
        '''
        INSERT INTO dose_history(
            user_id, medication_id, medication_name, schedule_time, taken_at, taken_date, status
        ) VALUES (?, ?, ?, ?, ?, ?, 'missed')
        ''',
        (
            session['user_id'], medication_id, medication['name'],
            medication['schedule_time'], utc_now().isoformat(timespec='seconds'), missed_date,
        ),
    )
    database.commit()
    return jsonify({'ok': True, 'status': 'missed'})


@app.delete('/api/medications/<int:medication_id>')
@login_required
def delete_medication(medication_id):
    database = get_db()
    cursor = database.execute(
        'DELETE FROM medications WHERE id = ? AND user_id = ?',
        (medication_id, session['user_id']),
    )
    database.commit()
    if cursor.rowcount == 0:
        return jsonify({'error': 'Yeh dawa nahi mili.'}), 404
    return jsonify({'ok': True})


@app.get('/api/history')
@login_required
def medication_history():
    today = date.today()
    first_day = (today - timedelta(days=6)).isoformat()
    database = get_db()
    database.execute('DELETE FROM dose_history WHERE taken_date < ?', (first_day,))
    database.execute(
        'DELETE FROM password_reset_codes WHERE expires_at < ?', (utc_now().isoformat(),)
    )
    database.commit()
    rows = database.execute(
        '''
        SELECT medication_name, schedule_time, taken_at, taken_date, status
        FROM dose_history
        WHERE user_id = ? AND taken_date >= ? AND taken_date <= ?
        ORDER BY taken_date DESC, schedule_time DESC, id DESC
        ''',
        (session['user_id'], first_day, today.isoformat()),
    ).fetchall()
    return jsonify({'history': [dict(row) for row in rows]})


@app.post('/ask')
@rate_limited('assistant', 30, 60)
def ask_ai():
    data, error = request_data()
    if error:
        return error
    user_question = data.get('question', '')
    language = data.get('language', 'hi')
    if language not in ('en', 'hi'):
        return jsonify({'answer': 'Please choose English or Hindi.'}), 400
    if not isinstance(user_question, str) or not user_question.strip():
        message = (
            'Please describe your symptoms or ask a question.'
            if language == 'en'
            else 'कृपया अपने लक्षण लिखें या सवाल पूछें।'
        )
        return jsonify({'answer': message}), 400
    if len(user_question) > 2000:
        message = (
            'Please keep your question under 2,000 characters.'
            if language == 'en'
            else 'कृपया सवाल 2,000 अक्षरों से छोटा रखें।'
        )
        return jsonify({'answer': message}), 400

    question = user_question.casefold()
    answer_index = 1 if language == 'en' else 2
    answers = []
    for health_tip in HEALTH_TIPS:
        keywords = health_tip[0]
        if any(keyword in question for keyword in keywords):
            answers.append(health_tip[answer_index])

    medicine_answers = []
    for medicine in MEDICINE_INFO:
        aliases = medicine[0]
        if any(
            re.search(r'(?<!\w)' + re.escape(alias) + r'(?!\w)', question)
            for alias in aliases
        ):
            medicine_answers.append(medicine[answer_index])

    if medicine_answers:
        answers.extend(medicine_answers)

    medicine_question = any(
        keyword in question
        for keyword in (
            'medicine', 'medicines', 'medication', 'medications', 'tablet', 'tablets',
            'दवा', 'दवाई', 'दवाइयाँ', 'गोली', 'गोलियाँ', 'कौन सी दवा', 'kaunsi dawa',
            'kaunsi dawai', 'konsi dawa',
        )
    )
    if medicine_question and not medicine_answers:
        answers.append(
            'I cannot choose a medicine or dose for you. The assistant only provides general information about a few common medicines; ask a doctor or pharmacist for advice based on your symptoms, age, health conditions, allergies, and other medicines.'
            if language == 'en'
            else 'मैं आपके लिए दवा या खुराक तय नहीं कर सकता। सहायक कुछ आम दवाओं की सामान्य जानकारी देता है; आपके लक्षण, उम्र, स्वास्थ्य, एलर्जी और दूसरी दवाओं के अनुसार सलाह के लिए डॉक्टर या फार्मासिस्ट से पूछें।'
        )

    if not answers:
        answer = 'I can share general tips for colds/cough/fever, sore throat, diarrhoea, constipation, heartburn, mild headaches, and allergies, plus basic information about paracetamol, ibuprofen, cetirizine, ORS, antacids, acid reducers, and antibiotics. For other conditions or personal medicine advice, contact a doctor or pharmacist.' if language == 'en' else 'मैं सर्दी/खाँसी/बुखार, गले के दर्द, दस्त, कब्ज़, सीने की जलन, हल्के सिरदर्द और एलर्जी पर सामान्य सुझाव दे सकता हूँ। पैरासिटामोल, इबुप्रोफेन, सेटिरिज़िन, ओआरएस, एंटासिड, एसिड कम करने वाली दवाओं और एंटीबायोटिक की सामान्य जानकारी भी दे सकता हूँ। अन्य समस्याओं या व्यक्तिगत दवा की सलाह के लिए डॉक्टर या फार्मासिस्ट से संपर्क करें।'
    else:
        safety_note = (
            '\n\nThis is general self-care information, not a diagnosis or personal prescription. '
            'Ask a doctor or pharmacist before taking medicine for a child, during pregnancy, '
            'with a chronic condition or allergy, or when using other medicines. Seek urgent '
            'medical help for breathing difficulty, fainting/confusion, dehydration, a very '
            'high or persistent fever, or worsening symptoms.'
            if language == 'en'
            else '\n\nयह सामान्य देखभाल की जानकारी है, बीमारी की पहचान या व्यक्तिगत दवा का नुस्खा नहीं। '
            'बच्चों, गर्भावस्था, पुरानी बीमारी, एलर्जी या अन्य दवाओं के साथ कोई दवा लेने से पहले '
            'डॉक्टर या फार्मासिस्ट से पूछें। साँस लेने में परेशानी, बेहोशी/भ्रम, शरीर में पानी की '
            'कमी, बहुत तेज़ या लगातार बुखार, या हालत बिगड़ने पर तुरंत चिकित्सा सहायता लें।'
        )
        answer = '\n\n'.join(answers) + safety_note
    heading = '🏥 MedConnect Health Information\n\n' if language == 'en' else '🏥 MedConnect स्वास्थ्य जानकारी\n\n'
    return jsonify({'answer': heading + answer})


initialize_db()


if __name__ == '__main__':
    from waitress import serve

    serve(
        app,
        host=os.environ.get('HOST', '0.0.0.0'),
        port=int(os.environ.get('PORT', '5000')),
        threads=32,
    )
