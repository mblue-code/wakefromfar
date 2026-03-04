# WakeFromFar Datenschutzerklärung (Deutsch)

Gültig ab: 2026-03-04  
Zuletzt aktualisiert: 2026-03-04

Diese Datenschutzerklärung erläutert, wie personenbezogene Daten verarbeitet werden, wenn du die WakeFromFar-Android-App und zugehörige Backend-Dienste nutzt.

Rechtlicher Hinweis: Dieses Dokument ist eine operative Richtlinie für dieses Projekt und stellt keine Rechtsberatung dar.

## 1. Wer ist verantwortlich

### 1.1 App-Herausgeber (Google Play)

Verantwortlicher für App-Distribution und Support:

- Organisationsname: `[ORGANISATIONSNAME EINTRAGEN]`
- Anschrift: `[GESCHÄFTSANSCHRIFT EINTRAGEN]`
- E-Mail: `[DATENSCHUTZ-KONTAKT EINTRAGEN]`

### 1.2 Backend-Betreiber (Self-Hosting-Umgebung)

WakeFromFar ist für den Self-Hosting-Betrieb ausgelegt. Die Organisation oder der Administrator, der deine Backend-Instanz betreibt, ist in der Regel der Verantwortliche für die dort verarbeiteten Backend-Daten.

Wenn dein Administrator das Backend betreibt, kontaktiere bei Anfragen zu Backend-Logs, Benutzerkonten und Gerätezuweisungen zuerst diesen Administrator.

## 2. Geltungsbereich

Diese Erklärung gilt für:

- WakeFromFar Android-App
- WakeFromFar Backend-APIs und Admin-UI (wenn durch oder im Auftrag des Verantwortlichen betrieben)
- Google Play Billing-Abläufe (wenn in der App aktiviert)

## 3. Welche Daten wir verarbeiten

Die konkret verarbeiteten Daten hängen von deiner Rolle (User/Admin) und den aktivierten Funktionen ab.

### 3.1 Konto- und Authentifizierungsdaten

- Benutzername
- Passwort-Hash im Backend (kein Klartext-Passwort)
- Lokal auf dem Gerät gespeichertes Authentifizierungs-Token nach dem Login

### 3.2 App-Konfiguration und lokale App-Daten (auf deinem Gerät)

- Backend-URL
- Zuletzt gesehene Aktivitäts-IDs für Admin-Hinweise
- App-Einstellungen (z. B. Theme/Sprache/Onboarding-Status)
- Lokaler Monetarisierungsstatus (z. B. Pro-Freischaltung und Schlüssel zur Reihenfolge im kostenlosen Modus)

Hinweis: Sicherheitsrelevante Sitzungsdaten werden auf Android in verschlüsselten Shared Preferences gespeichert.

### 3.3 Geräte- und Infrastrukturdaten (Backend)

- Zugewiesene Gerätemetadaten (z. B. Gerätename, MAC-Adresse, Broadcast-/Subnetz-/Source-IP-Konfiguration)
- Power-Check-Einstellungen und -Status (z. B. Check-Target, Check-Port, letzter bekannter Status)

### 3.4 Betriebs- und Audit-Logs (Backend)

- Wake-Ereignisse (Akteur, Ziel, Ergebnis, Zeitstempel)
- Power-Check-Ereignisse (Methode, Ergebnis, Detail, Latenz, Zeitstempel)
- Admin-Audit-Logs (Akteur, Aktion, Ziel, Detail, Zeitstempel)
- Invite-Token-Metadaten (gehashter Token, Benutzername, Erstell- und Einlöse-Status)
- Discovery-Ereignisse/-Kandidaten (für Netzwerk-/Geräte-Discovery-Funktionen, falls genutzt)

### 3.5 Netzwerk- und Sicherheitsmetadaten

- Request-IP-Adresse und verwandte Metadaten zur Login-Absicherung, Rate-Limiting und Missbrauchsprävention

### 3.6 Billing-Daten (nur wenn Käufe aktiviert sind)

- Produktkennungen und Kauf-Token/Transaktionskennungen zur Entitlement-Prüfung
- Die Zahlungsabwicklung erfolgt über Google Play gemäß den Google-Bedingungen
- Vollständige Kartendaten werden nicht vom WakeFromFar-Backend verarbeitet

## 4. Zwecke der Datenverarbeitung

Wir verarbeiten Daten, um:

- Login, Onboarding und authentifizierten App-Zugriff bereitzustellen
- Zugewiesene Geräte und deren Status anzuzeigen
- Wake- und Power-Check-Aktionen auszuführen
- Admin-Aktivität, Diagnostik sowie Sicherheits-/Audit-Funktionen bereitzustellen
- Schutzmaßnahmen gegen Missbrauch umzusetzen (z. B. Rate Limits)
- Bezahlfunktionen bereitzustellen und zu verifizieren (wenn Billing aktiviert ist)
- Stabilität, Fehleranalyse und Incident Response sicherzustellen

## 5. Rechtsgrundlagen (DSGVO, soweit anwendbar)

Je nach Kontext stützen wir die Verarbeitung auf:

- Art. 6 Abs. 1 lit. b DSGVO (Vertragserfüllung / Leistungserbringung)
- Art. 6 Abs. 1 lit. f DSGVO (berechtigte Interessen: Sicherheit, Betrugsprävention, Service-Integrität, Fehleranalyse)
- Art. 6 Abs. 1 lit. c DSGVO (rechtliche Verpflichtungen), soweit erforderlich

Falls besondere Kategorien personenbezogener Daten verarbeitet würden (für diesen Dienst normalerweise nicht vorgesehen), sind zusätzliche Rechtsgrundlagen erforderlich.

## 6. Weitergabe von Daten

Wir verkaufen keine personenbezogenen Daten.

Daten können weitergegeben werden an:

- Hosting-/Infrastruktur-Anbieter des Backend-Betreibers
- Dienstleister, die als Auftragsverarbeiter auf Weisung tätig sind
- Google (für Play-Store-Distribution und Play Billing, wenn aktiviert)
- Behörden, soweit gesetzlich erforderlich

## 7. Internationale Datenübermittlungen

Wenn Anbieter Daten außerhalb deines Landes bzw. außerhalb des EWR verarbeiten, sollten durch den jeweils Verantwortlichen geeignete Garantien umgesetzt werden (z. B. Standardvertragsklauseln, soweit erforderlich).

## 8. Speicherdauer

- Der App-Herausgeber betreibt in dieser Projektarchitektur standardmäßig keine zentrale Cloud für Wake-Aktivitäten.
- Backend-Daten werden vom Backend-Betreiber so lange gespeichert, wie es für Betrieb, Sicherheit und Support erforderlich ist, sofern sie nicht vorher gelöscht werden.
- Lokal auf dem Gerät gespeicherte App-Daten bleiben bis zum Logout, Zurücksetzen der App-Daten oder zur Deinstallation erhalten.
- Billing-bezogene Kennungen werden so lange gespeichert, wie es für Entitlement-Prüfung, Abrechnung und Betrugsprävention erforderlich ist.

Du solltest konkrete Aufbewahrungsfristen in deiner Betriebsrichtlinie definieren und umsetzen.

## 9. Sicherheitsmaßnahmen

Mögliche Maßnahmen umfassen:

- Token-basierte Authentifizierung
- Passwort-Hashing im Backend
- Verschlüsselte lokale Speicherung sensibler Sitzungsdaten
- Zugriffskontrollen und Rollentrennung (Admin/User)
- Rate Limiting und Sicherheitsprotokollierung
- Empfehlungen für private Netzwerke (z. B. WireGuard/Tailscale)

Kein System ist vollständig risikofrei; Sicherheitsmaßnahmen werden laufend überprüft und verbessert.

## 10. Deine Rechte

Soweit gesetzlich vorgesehen, kannst du folgende Rechte geltend machen:

- Auskunft über deine personenbezogenen Daten
- Berichtigung unrichtiger Daten
- Löschung von Daten
- Einschränkung der Verarbeitung
- Datenübertragbarkeit
- Widerspruch gegen bestimmte Verarbeitungen
- Widerruf einer Einwilligung (wenn die Verarbeitung auf Einwilligung beruht)

Du kannst außerdem eine Beschwerde bei der zuständigen Datenschutzaufsichtsbehörde einreichen.

## 11. So kannst du deine Rechte ausüben

Für Daten in deiner Backend-Instanz kontaktiere zuerst deinen Backend-Administrator.  
Für Anfragen an den App-Herausgeber kontaktiere: `[DATENSCHUTZ-KONTAKT EINTRAGEN]`.

Vor der Bearbeitung können wir eine angemessene Identitätsprüfung verlangen.

## 12. Datenschutz von Kindern

Dieser Dienst richtet sich nicht an Kinder unter dem Alter, das nach anwendbarem Recht für eine eigenständige Einwilligung in digitale Dienste erforderlich ist.

## 13. Änderungen dieser Erklärung

Wir können diese Erklärung von Zeit zu Zeit aktualisieren. Wesentliche Änderungen werden durch das Aktualisieren des Datums "Zuletzt aktualisiert" kenntlich gemacht und, sofern erforderlich, zusätzlich bekannt gegeben.
