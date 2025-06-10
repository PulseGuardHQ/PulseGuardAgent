# PulseGuard Agent voor Windows

Een krachtige Windows agent voor het monitoren en beheren van systemen via de PulseGuard platform.

## Kenmerken

- **Automatische System Monitoring**: Verzamelt real-time metrics van CPU, geheugen, schijf en netwerk
- **Remote Management**: SSH, RDP en VNC ondersteuning voor externe toegang
- **Power Management**: Vergrendelen, slaapstand, herstarten en afsluiten via de API
- **Betrouwbare Auto-Start**: Meerdere methoden voor automatisch opstarten bij system boot
- **Automatische Updates**: Controleert en installeert updates automatisch
- **Robuuste Cleanup**: Verwijdert oude versies en configuraties automatisch

## Auto-Start Functionaliteit

De agent gebruikt meerdere methoden om betrouwbaar automatisch op te starten:

### Methoden:
1. **Auto-Launch Library**: Primaire methode voor backwards compatibility
2. **Windows Registry**: Backup methode via Run keys (HKCU en HKLM)
3. **Task Scheduler**: Meest betrouwbare methode voor Windows services
4. **Startup Folders**: Fallback voor speciale configuraties

### Voordelen:
- **Redundantie**: Als één methode faalt, werken de anderen nog
- **Compatibiliteit**: Werkt met zowel portable als geïnstalleerde versies
- **Admin Support**: Ondersteunt zowel gebruiker- als admin-level startup
- **Self-Healing**: Herconfigureert automatisch bij problemen

## Cleanup Functionaliteit

### Oude Versies Verwijdering:
- **Proces Terminatie**: Stopt oude versies voordat ze verwijderd worden
- **Bestand Cleanup**: Verwijdert oude executable bestanden
- **Registry Cleanup**: Ruimt oude registry entries op
- **Task Cleanup**: Verwijdert oude scheduled tasks
- **Startup Cleanup**: Ruimt oude startup shortcuts op

### Verbeterde Betrouwbaarheid:
- **Synchrone Operaties**: Wacht op voltooiing van cleanup acties
- **Error Handling**: Faalt gracefully bij problemen
- **Backup Strategieën**: Hernoemt bestanden als verwijdering faalt
- **Version Detection**: Verwijdert alleen daadwerkelijk oude versies

## Bouwen

### Alle Versies:
```bash
npm run build-all
```

### Alleen Installer:
```bash
npm run build-installer
```

### Alleen Portable:
```bash
npm run build-portable
```

## Installatie Types

### NSIS Installer (Aanbevolen)
- Volledige installatie met auto-startup configuratie
- Automatische cleanup van oude versies
- Start Menu en Desktop shortcuts
- Proper uninstall ondersteuning

### Portable Versie
- Geen installatie vereist
- Zelf-configurerende auto-startup
- Ideaal voor USB drives of tijdelijk gebruik

## Configuratie

De agent wordt automatisch geconfigureerd bij de eerste start. Handmatige configuratie is mogelijk via:

1. **UI Interface**: Open de agent en ga naar instellingen
2. **Config Bestand**: Bewerk `config.json` in de applicatie directory
3. **API Endpoints**: Gebruik de REST API voor remote configuratie

## Auto-Start Status Controleren

Vanuit de UI kun je de auto-start status controleren:
- Ga naar Instellingen → Auto-Start Status
- Bekijk welke methoden actief zijn
- Forceer herconfiguratie indien nodig

## Troubleshooting

### Auto-Start Werkt Niet:
1. Controleer admin rechten (run as administrator)
2. Controleer Windows Security instellingen
3. Gebruik de "Force Auto-Start Setup" optie in de UI
4. Check de log bestanden voor error messages

### Oude Versies Blijven Achter:
1. Stop alle PulseGuard processen handmatig
2. Run de "Cleanup Old Versions" optie in de UI
3. Herstart de agent om cleanup te voltooien

### Performance Issues:
1. Verhoog het check interval in instellingen
2. Schakel onnodige monitoring uit
3. Check voor conflicterende software

## Log Bestanden

Logs worden opgeslagen in:
- `%APPDATA%/PulseGuard/logs/`
- `%LOCALAPPDATA%/PulseGuard/logs/`

## Support

Voor ondersteuning, documentatie en updates:
- Check de applicatie logs voor foutmeldingen
- Gebruik de "Send Metrics Now" functie voor diagnostics
- Contact support via de PulseGuard platform

## Changelog

### Versie 1.1.1+
- **Verbeterde Auto-Start**: Meerdere backup methoden voor betrouwbaarheid
- **Betere Cleanup**: Synchrone operaties en error handling
- **NSIS Installer**: Professionele installatie met auto-configuratie
- **Self-Healing**: Automatische herconfiguratie bij problemen
- **Enhanced Logging**: Meer gedetailleerde diagnostics 