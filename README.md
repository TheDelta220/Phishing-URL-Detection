# Phishing-URL-Detection
## Requirements
- Python 3.12.8
- Packages: `pandas`, `numpy`, `scikit-learn`, `scipy`, `matplotlib`, `tqdm`, `jupyter`

```
pip install pandas numpy scikit-learn scipy matplotlib tqdm jupyter
```
## How to run
1. Open `Phishing_URL_Detection.ipynb` in Jupyter or VS Code.
2. Choose **Restart kernel, then Run All**.


## THREAT MODEL
The people who wants to attack our application are phishers who wants their malicious URL to be passed off as a legitimate URL, or an attacker that aims to disrupt the phishing detection service in order to cut their victims from these services. They would want to bypass phishing detection by manipulating or interfering with stored data in our database. Attackers that aim to disrupt the phishing detection service would want the application to be unavailable to the legitimate users. The attacks that they can implement includes specially crafted URLs for an SQL Injection in order to gather and change database queries, sending a large amount of slow prediction requests for a Denial of Service attack which makes the application inaccessible by users, or modifying their phishing URLs using similar Unicode characters to trick the model to evade detection.

Defending against SQL Injection is relevant because the application accepts URLs that the user can submit, which then stores the prediction history in a database. This attack can then compromise the integrity of our application because when the attacker gains access to database, they can modify and delete stored records which greatly impacts the user history and stored data. The reliability of a phishing detection system lies within trustworthiness of its data, so an SQL Injection attack would threaten to compromise the entire application.
Defending against DoS attack is also important because the application uses machine learning inferences for URL checking, which consumes processing resource. So, when the attacker send a large amount of slow requests simultaneously, the backend will get overloaded which makes legitimate requests very slow or outright fail. We need to keep the service accessible at all times for users.

## 2.7 DEFENCES
SQL Injection: Intermediate 
Denial of Service (DoS): Advanced

## 2.8 ADVANCED DEFENCES
API Attack on the model: Detection Evasion 



## REFERENCES

Amazon Web Services (2026) *Securing Amazon Bedrock Agents: A guide to safeguarding against indirect prompt injections*
Available at: https://aws.amazon.com/blogs/machine-learning/securing-amazon-bedrock-agents-a-guide-to-safeguarding-against-indirect-prompt-injections/ (Accessed: 9/11)

Cloudflare (n.d.) *Denial of Service (DoS)*
Available at: https://www.cloudflare.com/learning/ddos/glossary/denial-of-service/ (Accessed: 6/11)

Cloudflare (n.d.) *What is prompt injection?* 
Available at: https://www.cloudflare.com/learning/ai/prompt-injection/ (Accessed: 9/11)

curl (2009) *Visual Studio libcurl* 
Available at: https://curl.se/mail/lib-2009-04/att-0198/visual_studio_libcurl.pdf (Accessed: 8/11)

FastAPI (n.d.) *FastAPI Documentation*
Available at: https://fastapi.tiangolo.com/ (Accessed: 22/10)

Internet Engineering Task Force (2010) *RFC 3492: Punycode: A Bootstring encoding of Unicode for Internationalized Domain Names in Applications (IDNA)*
Available at: https://www.rfc-editor.org/rfc/rfc3492 (Accessed: 26/10)

Internet Engineering Task Force (2022) *RFC 9110: HTTP Semantics*
Available at: https://www.rfc-editor.org/rfc/rfc9110 (Accessed: 26/10)

Invicti (n.d.) *SQL injection cheat sheet* 
Available at: https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet (Accessed: 6/11)

Kaggle (n.d.) *Malicious URLs Dataset*
Available at: https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset (Accessed: 20/10)

MDN Web Docs (n.d.) *MDN Web Docs*
Available at: https://developer.mozilla.org/en-US/ (Accessed: 19 October 2026)

Microsoft (n.d.) *curl in Windows*
Available at: https://learn.microsoft.com/en-us/windows/curl/ (Accessed: 8/11)

Node.js (n.d.) *Node.js*
Available at: https://nodejs.org/en (Accessed: 13 October 2026)

Penetration Testing Tools (n.d.) *SQL injection attacks*
Available at: https://pentest-tools.com/blog/sql-injection-attacks (Accessed: 6/11)

Picsvg (n.d.) *Picsvg*
Available at: https://picsvg.com/ (Accessed: 14 October 2026)

Postman (n.d.) *GET vs POST: What's the difference?* 
Available at: https://blog.postman.com/get-vs-post/ (Accessed: 9/11)

Pydantic (n.d.) *Pydantic Documentation*
Available at: https://docs.pydantic.dev/ (Accessed: 23/10)

React (n.d.) *React*
Available at: https://react.dev/ (Accessed: 13 October 2026)

Recharts (n.d.) *Recharts Documentation*
Available at: https://recharts.org/ (Accessed: 22/10)

Uvicorn (n.d.) *Uvicorn*
Available at: https://uvicorn.dev/ (Accessed: 3 November 2026)

Vite (n.d.) *Vite*
Available at: https://vite.dev/ (Accessed: 14 October 2026)

W3Schools (n.d.) *CSS Tutorial*
Available at: https://www.w3schools.com/css/default.asp (Accessed: 13 October 2026)

W3Schools (n.d.) *HTML Tutorial*
Available at: https://www.w3schools.com/html/default.asp (Accessed: 13 October 2026)

W3Schools (n.d.) *HTTP Methods*
Available at: https://www.w3schools.com/tags/ref_httpmethods.asp (Accessed: 9/11)

W3Schools (n.d.) *JavaScript Tutorial*
Available at: https://www.w3schools.com/js/default.asp (Accessed: 13 October 2026)

W3Schools (n.d.) *Python Tutorial*
Available at: https://www.w3schools.com/python/default.asp (Accessed: 13 October 2026)

W3Schools (n.d.) *React Tutorial*
Available at: https://www.w3schools.com/react/default.asp (Accessed: 13 October 2026)

W3Schools (n.d.) *SQL Injection*
Available at: https://www.w3schools.com/sql/sql_injection.asp (Accessed: 6/11)

W3Schools (n.d.) *SQL Syntax*
Available at: https://www.w3schools.com/sql/sql_syntax.asp (Accessed: 8/11)

YouTube (2021) *React JS Explained In 10 Minutes - Dennis Ivy*
Available at: https://youtu.be/s2skans2dP4 (Accessed: 22 October 2026)
