# backend מוכן - הקלדת מילים בעברית

מה תוקן:
- כפתור "התחל לשחק" עובד ועובר ל-`/game.html`
- נוספו API אמיתיים ל-SMS ולאימייל
- אם תחבר Twilio Verify, ה-SMS יישלח באמת
- אם תחבר SMTP, האימייל יישלח באמת

## הפעלה מקומית
```bash
npm install
cp .env.example .env
npm start
```

## פריסה ל-Render
1. העלה את כל התיקייה ל-GitHub
2. פתח חשבון Render
3. צור Web Service חדש מה-repo
4. Start command:
   npm start
5. הוסף Environment Variables מתוך `.env.example`

## חיבור SMS אמיתי
מומלץ Twilio Verify:
- TWILIO_ACCOUNT_SID
- TWILIO_AUTH_TOKEN
- TWILIO_VERIFY_SERVICE_SID

## חיבור אימייל אמיתי
- SMTP_HOST
- SMTP_PORT
- SMTP_USER
- SMTP_PASS
- MAIL_FROM

## הערה
אם אין חיבור אמיתי לשירות, השרת יכול לעבוד במצב בדיקה בלבד.
