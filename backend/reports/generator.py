"""
Générateur de rapports
Formats: JSON, HTML (OSCP/Client), Markdown, PDF
"""
import os
import json
import subprocess
from datetime import datetime
from typing import Dict, Any, List, Optional
from jinja2 import Template

from core.config import settings

class ReportGenerator:
    """Génère des rapports de pentest en plusieurs formats"""
    
    # Formats supportés
    SUPPORTED_FORMATS = ["json", "oscp", "client", "markdown", "pdf"]
    
    def __init__(self):
        self.templates_dir = os.path.join(settings.BASE_DIR, "templates")
        os.makedirs(self.templates_dir, exist_ok=True)
        os.makedirs(settings.REPORTS_DIR, exist_ok=True)
    
    async def generate(
        self,
        report_type: str,
        targets: List[Dict[str, Any]],
        results: Dict[str, Dict[str, Any]],
        include_screenshots: bool = True,
        title: str = None,
        author: str = None,
        output_format: str = None
    ) -> Dict[str, Any]:
        """
        Génère un rapport selon le type et format demandés
        
        Args:
            report_type: Type de rapport (oscp, client)
            targets: Liste des cibles
            results: Résultats par cible
            include_screenshots: Inclure les captures d'écran
            title: Titre du rapport
            author: Auteur du rapport
            output_format: Format de sortie (html, markdown, pdf, json)
        
        Returns:
            Dict avec filename et formats générés
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_format = output_format or "html"
        generated_files = []
        
        if report_type == "json" or output_format == "json":
            filename = await self._generate_json(targets, results, timestamp)
            generated_files.append({"format": "json", "filename": filename})
        
        if report_type in ["oscp", "client"]:
            # Générer HTML
            if output_format in ["html", "all"]:
                filename = await self._generate_html(
                    report_type, targets, results, timestamp,
                    include_screenshots, title, author
                )
                generated_files.append({"format": "html", "filename": filename})
            
            # Générer Markdown
            if output_format in ["markdown", "md", "all"]:
                filename = await self._generate_markdown(
                    report_type, targets, results, timestamp,
                    title, author
                )
                generated_files.append({"format": "markdown", "filename": filename})
            
            # Générer PDF
            if output_format in ["pdf", "all"]:
                html_file = await self._generate_html(
                    report_type, targets, results, timestamp,
                    include_screenshots, title, author
                )
                pdf_filename = await self._convert_html_to_pdf(html_file, timestamp)
                if pdf_filename:
                    generated_files.append({"format": "pdf", "filename": pdf_filename})
        
        return {
            "status": "success",
            "generated": generated_files,
            "primary": generated_files[0]["filename"] if generated_files else None
        }
    
    async def _generate_json(
        self,
        targets: List[Dict[str, Any]],
        results: Dict[str, Dict[str, Any]],
        timestamp: str
    ) -> str:
        """Génère un export JSON"""
        filename = f"report_{timestamp}.json"
        filepath = os.path.join(settings.REPORTS_DIR, filename)
        
        report_data = {
            "generated_at": datetime.now().isoformat(),
            "targets": targets,
            "results": results,
            "vulnerabilities": self._extract_vulnerabilities(results),
            "statistics": self._calculate_statistics(results)
        }
        
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        return filename
    
    async def _generate_html(
        self,
        report_type: str,
        targets: List[Dict[str, Any]],
        results: Dict[str, Dict[str, Any]],
        timestamp: str,
        include_screenshots: bool,
        title: str,
        author: str
    ) -> str:
        """Génère un rapport HTML (OSCP ou Client)"""
        if report_type == "oscp":
            filename = f"oscp_report_{timestamp}.html"
            html = self._render_oscp_template(
                targets=targets,
                results=results,
                include_screenshots=include_screenshots,
                title=title or "Penetration Test Report",
                author=author or "Security Analyst",
                date=datetime.now().strftime("%Y-%m-%d")
            )
        else:  # client
            filename = f"client_report_{timestamp}.html"
            html = self._render_client_template(
                targets=targets,
                results=results,
                include_screenshots=include_screenshots,
                title=title or "Security Assessment Report",
                author=author or "Security Consultant",
                date=datetime.now().strftime("%Y-%m-%d")
            )
        
        filepath = os.path.join(settings.REPORTS_DIR, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return filename
    
    async def _generate_markdown(
        self,
        report_type: str,
        targets: List[Dict[str, Any]],
        results: Dict[str, Dict[str, Any]],
        timestamp: str,
        title: str,
        author: str
    ) -> str:
        """Génère un rapport Markdown"""
        filename = f"report_{timestamp}.md"
        filepath = os.path.join(settings.REPORTS_DIR, filename)
        
        vulnerabilities = self._extract_vulnerabilities(results)
        ports_by_target = self._extract_open_ports(results)
        vuln_stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in vulnerabilities:
            sev = vuln["severity"].lower()
            if sev in vuln_stats:
                vuln_stats[sev] += 1
        
        md_content = self._render_markdown_template(
            title=title or "Security Assessment Report",
            author=author or "Security Analyst",
            date=datetime.now().strftime("%Y-%m-%d"),
            targets=targets,
            results=results,
            vulnerabilities=vulnerabilities,
            ports_by_target=ports_by_target,
            vuln_stats=vuln_stats
        )
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(md_content)
        
        return filename
    
    async def _convert_html_to_pdf(self, html_filename: str, timestamp: str) -> Optional[str]:
        """Convertit un rapport HTML en PDF"""
        html_path = os.path.join(settings.REPORTS_DIR, html_filename)
        pdf_filename = html_filename.replace('.html', '.pdf')
        pdf_path = os.path.join(settings.REPORTS_DIR, pdf_filename)
        
        # Essayer avec wkhtmltopdf
        try:
            result = subprocess.run(
                ['wkhtmltopdf', '--quiet', '--page-size', 'A4', 
                 '--margin-top', '10mm', '--margin-bottom', '10mm',
                 '--margin-left', '10mm', '--margin-right', '10mm',
                 html_path, pdf_path],
                capture_output=True,
                timeout=120
            )
            if result.returncode == 0 and os.path.exists(pdf_path):
                return pdf_filename
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        
        # Essayer avec weasyprint (Python)
        try:
            from weasyprint import HTML
            HTML(html_path).write_pdf(pdf_path)
            if os.path.exists(pdf_path):
                return pdf_filename
        except ImportError:
            pass
        except Exception as e:
            print(f"[Report] Erreur weasyprint: {e}")
        
        return None
    
    def _calculate_statistics(self, results: Dict[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Calcule les statistiques des résultats"""
        stats = {
            "total_actions": 0,
            "completed_actions": 0,
            "failed_actions": 0,
            "total_duration": 0,
            "targets_scanned": len(results)
        }
        
        for target_id, target_results in results.items():
            for action, result in target_results.items():
                if isinstance(result, dict):
                    stats["total_actions"] += 1
                    if result.get("status") == "completed":
                        stats["completed_actions"] += 1
                    else:
                        stats["failed_actions"] += 1
                    stats["total_duration"] += result.get("duration", 0)
        
        return stats
    
    def _render_markdown_template(self, **kwargs) -> str:
        """Génère le contenu Markdown du rapport"""
        template = Template(MARKDOWN_TEMPLATE)
        return template.render(**kwargs)
    
    async def _generate_oscp(
        self,
        targets: List[Dict[str, Any]],
        results: Dict[str, Dict[str, Any]],
        timestamp: str,
        include_screenshots: bool,
        title: str,
        author: str
    ) -> str:
        """Génère un rapport style OSCP (legacy)"""
        return await self._generate_html("oscp", targets, results, timestamp, 
                                         include_screenshots, title, author)
        
        html = self._render_oscp_template(
            targets=targets,
            results=results,
            include_screenshots=include_screenshots,
            title=title or "Penetration Test Report",
            author=author or "Security Analyst",
            date=datetime.now().strftime("%Y-%m-%d")
        )
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return filename
    
    async def _generate_client(
        self,
        targets: List[Dict[str, Any]],
        results: Dict[str, Dict[str, Any]],
        timestamp: str,
        include_screenshots: bool,
        title: str,
        author: str
    ) -> str:
        """Génère un rapport professionnel pour client"""
        filename = f"client_report_{timestamp}.html"
        filepath = os.path.join(settings.REPORTS_DIR, filename)
        
        html = self._render_client_template(
            targets=targets,
            results=results,
            include_screenshots=include_screenshots,
            title=title or "Security Assessment Report",
            author=author or "Security Consultant",
            date=datetime.now().strftime("%Y-%m-%d")
        )
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return filename
    
    def _get_severity_class(self, severity: str) -> str:
        """Retourne la classe CSS pour une sévérité"""
        classes = {
            "critical": "severity-critical",
            "high": "severity-high",
            "medium": "severity-medium",
            "low": "severity-low",
            "info": "severity-info"
        }
        return classes.get(severity.lower(), "severity-info")
    
    def _extract_vulnerabilities(self, results: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extrait toutes les vulnérabilités des résultats"""
        vulns = []
        
        for target_id, target_results in results.items():
            for action, result in target_results.items():
                if not isinstance(result, dict):
                    continue
                    
                parsed = result.get("parsed_data", {})
                
                # Nuclei findings
                if action in ["nuclei", "nuclei_network"]:
                    for finding in parsed.get("findings", []):
                        vulns.append({
                            "target_id": target_id,
                            "source": action,
                            "name": finding.get("name", ""),
                            "severity": finding.get("severity", "info"),
                            "description": finding.get("description", ""),
                            "location": finding.get("matched_at", ""),
                            "references": finding.get("reference", [])
                        })
                
                # Nikto findings
                elif action == "nikto":
                    for finding in parsed.get("vulnerabilities", []):
                        vulns.append({
                            "target_id": target_id,
                            "source": action,
                            "name": finding,
                            "severity": "medium",
                            "description": finding,
                            "location": result.get("target", ""),
                            "references": []
                        })
                
                # Nmap vuln scripts
                elif action in ["nmap_vuln", "nmap_vulners"]:
                    for vuln in parsed.get("vulnerabilities", []):
                        vulns.append({
                            "target_id": target_id,
                            "source": action,
                            "name": vuln.get("cve", vuln.get("name", "")),
                            "severity": "high",
                            "description": "",
                            "location": result.get("target", ""),
                            "references": []
                        })
        
        # Trier par sévérité
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        vulns.sort(key=lambda x: severity_order.get(x["severity"].lower(), 5))
        
        return vulns
    
    def _extract_open_ports(self, results: Dict[str, Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Extrait les ports ouverts par cible"""
        ports_by_target = {}
        
        for target_id, target_results in results.items():
            ports = []
            for action in ["nmap_quick", "nmap_full"]:
                if action in target_results:
                    result = target_results[action]
                    parsed = result.get("parsed_data", {})
                    for host in parsed.get("hosts", []):
                        for port in host.get("ports", []):
                            if port["state"] == "open":
                                ports.append(port)
            ports_by_target[target_id] = ports
        
        return ports_by_target
    
    def _render_oscp_template(self, **kwargs) -> str:
        """Rendu du template OSCP"""
        template = Template(OSCP_TEMPLATE)
        
        # Préparer les données
        kwargs["vulnerabilities"] = self._extract_vulnerabilities(kwargs["results"])
        kwargs["ports_by_target"] = self._extract_open_ports(kwargs["results"])
        kwargs["get_severity_class"] = self._get_severity_class
        
        return template.render(**kwargs)
    
    def _render_client_template(self, **kwargs) -> str:
        """Rendu du template Client"""
        template = Template(CLIENT_TEMPLATE)
        
        # Préparer les données
        kwargs["vulnerabilities"] = self._extract_vulnerabilities(kwargs["results"])
        kwargs["ports_by_target"] = self._extract_open_ports(kwargs["results"])
        kwargs["get_severity_class"] = self._get_severity_class
        
        # Calculer les statistiques
        vuln_stats = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for vuln in kwargs["vulnerabilities"]:
            sev = vuln["severity"].lower()
            if sev in vuln_stats:
                vuln_stats[sev] += 1
        kwargs["vuln_stats"] = vuln_stats
        
        return template.render(**kwargs)


# Template OSCP-style
OSCP_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px; }
        h1 { color: #c0392b; border-bottom: 3px solid #c0392b; padding-bottom: 10px; margin-bottom: 20px; }
        h2 { color: #2c3e50; margin-top: 30px; margin-bottom: 15px; border-left: 4px solid #3498db; padding-left: 10px; }
        h3 { color: #34495e; margin-top: 20px; margin-bottom: 10px; }
        .header { text-align: center; margin-bottom: 40px; padding: 20px; background: linear-gradient(135deg, #1a1a2e, #16213e); color: white; border-radius: 10px; }
        .header h1 { color: white; border-bottom: none; }
        .meta { display: flex; justify-content: space-around; margin-top: 20px; }
        .meta div { text-align: center; }
        .section { margin-bottom: 30px; padding: 20px; background: #f9f9f9; border-radius: 8px; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #3498db; color: white; }
        tr:hover { background: #f5f5f5; }
        .severity-critical { background: #c0392b; color: white; padding: 3px 8px; border-radius: 4px; font-weight: bold; }
        .severity-high { background: #e74c3c; color: white; padding: 3px 8px; border-radius: 4px; }
        .severity-medium { background: #f39c12; color: white; padding: 3px 8px; border-radius: 4px; }
        .severity-low { background: #3498db; color: white; padding: 3px 8px; border-radius: 4px; }
        .severity-info { background: #95a5a6; color: white; padding: 3px 8px; border-radius: 4px; }
        .port-open { color: #27ae60; font-weight: bold; }
        .code { background: #2c3e50; color: #ecf0f1; padding: 15px; border-radius: 5px; overflow-x: auto; font-family: 'Courier New', monospace; font-size: 12px; white-space: pre-wrap; word-break: break-all; margin: 10px 0; }
        .toc { background: #ecf0f1; padding: 20px; border-radius: 8px; margin-bottom: 30px; }
        .toc ul { list-style: none; }
        .toc li { padding: 5px 0; }
        .toc a { color: #3498db; text-decoration: none; }
        .toc a:hover { text-decoration: underline; }
        .screenshot { max-width: 100%; border: 1px solid #ddd; border-radius: 5px; margin: 10px 0; }
        @media print { .section { break-inside: avoid; } }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ title }}</h1>
        <div class="meta">
            <div><strong>Author:</strong> {{ author }}</div>
            <div><strong>Date:</strong> {{ date }}</div>
            <div><strong>Targets:</strong> {{ targets|length }}</div>
        </div>
    </div>
    
    <div class="toc">
        <h2>Table of Contents</h2>
        <ul>
            <li><a href="#executive-summary">1. Executive Summary</a></li>
            <li><a href="#targets">2. Targets</a></li>
            <li><a href="#findings">3. Findings</a></li>
            <li><a href="#enumeration">4. Enumeration Results</a></li>
            <li><a href="#exploitation">5. Exploitation Notes</a></li>
        </ul>
    </div>
    
    <div class="section" id="executive-summary">
        <h2>1. Executive Summary</h2>
        <p>This penetration test was conducted against {{ targets|length }} target(s). The assessment identified {{ vulnerabilities|length }} potential security issues.</p>
        
        <h3>Vulnerability Summary</h3>
        <table>
            <tr>
                <th>Severity</th>
                <th>Count</th>
            </tr>
            {% set stats = {} %}
            {% for vuln in vulnerabilities %}
                {% set _ = stats.update({vuln.severity: stats.get(vuln.severity, 0) + 1}) %}
            {% endfor %}
            {% for sev in ['critical', 'high', 'medium', 'low', 'info'] %}
            <tr>
                <td><span class="severity-{{ sev }}">{{ sev|upper }}</span></td>
                <td>{{ stats.get(sev, 0) }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
    
    <div class="section" id="targets">
        <h2>2. Targets</h2>
        <table>
            <tr>
                <th>ID</th>
                <th>Type</th>
                <th>Value</th>
                <th>Description</th>
            </tr>
            {% for target in targets %}
            <tr>
                <td>{{ target.id }}</td>
                <td>{{ target.type }}</td>
                <td><strong>{{ target.value }}</strong></td>
                <td>{{ target.description or '-' }}</td>
            </tr>
            {% endfor %}
        </table>
        
        <h3>Open Ports</h3>
        {% for target_id, ports in ports_by_target.items() %}
        <h4>Target {{ target_id }}</h4>
        {% if ports %}
        <table>
            <tr>
                <th>Port</th>
                <th>Protocol</th>
                <th>Service</th>
                <th>Version</th>
            </tr>
            {% for port in ports %}
            <tr>
                <td class="port-open">{{ port.port }}</td>
                <td>{{ port.protocol }}</td>
                <td>{{ port.service }}</td>
                <td>{{ port.version or '-' }}</td>
            </tr>
            {% endfor %}
        </table>
        {% else %}
        <p>No open ports discovered.</p>
        {% endif %}
        {% endfor %}
    </div>
    
    <div class="section" id="findings">
        <h2>3. Findings</h2>
        {% if vulnerabilities %}
        {% for vuln in vulnerabilities %}
        <div style="margin-bottom: 20px; padding: 15px; border-left: 4px solid 
            {% if vuln.severity == 'critical' %}#c0392b{% elif vuln.severity == 'high' %}#e74c3c{% elif vuln.severity == 'medium' %}#f39c12{% else %}#3498db{% endif %}; background: white;">
            <h4>
                <span class="severity-{{ vuln.severity }}">{{ vuln.severity|upper }}</span>
                {{ vuln.name }}
            </h4>
            <p><strong>Location:</strong> {{ vuln.location }}</p>
            <p><strong>Source:</strong> {{ vuln.source }}</p>
            {% if vuln.description %}
            <p><strong>Description:</strong> {{ vuln.description }}</p>
            {% endif %}
            {% if vuln.references %}
            <p><strong>References:</strong></p>
            <ul>
                {% for ref in vuln.references[:5] %}
                <li><a href="{{ ref }}" target="_blank">{{ ref }}</a></li>
                {% endfor %}
            </ul>
            {% endif %}
        </div>
        {% endfor %}
        {% else %}
        <p>No vulnerabilities identified during this assessment.</p>
        {% endif %}
    </div>
    
    <div class="section" id="enumeration">
        <h2>4. Enumeration Results</h2>
        {% for target_id, target_results in results.items() %}
        <h3>Target {{ target_id }}</h3>
        {% for action, result in target_results.items() %}
        {% if result.status == 'completed' %}
        <h4>{{ action }}</h4>
        <p><strong>Command:</strong></p>
        <div class="code">{{ result.command or 'N/A' }}</div>
        <p><strong>Duration:</strong> {{ "%.2f"|format(result.duration or 0) }}s</p>
        <details>
            <summary>View Output</summary>
            <div class="code">{{ result.output[:5000] if result.output else 'No output' }}{% if result.output and result.output|length > 5000 %}...truncated{% endif %}</div>
        </details>
        {% endif %}
        {% endfor %}
        {% endfor %}
    </div>
    
    <div class="section" id="exploitation">
        <h2>5. Exploitation Notes</h2>
        <p>Document your exploitation steps here during the engagement.</p>
        <div class="code"># Exploitation commands and notes
# Add your proof-of-concept here</div>
    </div>
    
    <footer style="text-align: center; margin-top: 40px; padding: 20px; color: #7f8c8d;">
        <p>Generated by HackInterface - {{ date }}</p>
    </footer>
</body>
</html>
"""

# Template Client professionnel
CLIENT_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.8; color: #2c3e50; }
        .container { max-width: 1000px; margin: 0 auto; padding: 40px; }
        .cover { height: 100vh; display: flex; flex-direction: column; justify-content: center; align-items: center; background: linear-gradient(135deg, #0f0c29, #302b63, #24243e); color: white; text-align: center; page-break-after: always; }
        .cover h1 { font-size: 3em; margin-bottom: 20px; }
        .cover .subtitle { font-size: 1.5em; color: #bdc3c7; margin-bottom: 40px; }
        .cover-meta { margin-top: 60px; }
        .cover-meta p { margin: 10px 0; font-size: 1.1em; }
        h1 { color: #2c3e50; margin-bottom: 20px; }
        h2 { color: #34495e; margin-top: 40px; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #3498db; }
        h3 { color: #5d6d7e; margin-top: 25px; margin-bottom: 15px; }
        p { margin-bottom: 15px; }
        .executive-summary { background: #f8f9fa; padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        .stats-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 15px; margin: 20px 0; }
        .stat-box { text-align: center; padding: 20px; border-radius: 8px; color: white; }
        .stat-box.critical { background: linear-gradient(135deg, #c0392b, #e74c3c); }
        .stat-box.high { background: linear-gradient(135deg, #d35400, #e67e22); }
        .stat-box.medium { background: linear-gradient(135deg, #f39c12, #f1c40f); }
        .stat-box.low { background: linear-gradient(135deg, #2980b9, #3498db); }
        .stat-box.info { background: linear-gradient(135deg, #7f8c8d, #95a5a6); }
        .stat-number { font-size: 2.5em; font-weight: bold; }
        .stat-label { font-size: 0.9em; text-transform: uppercase; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        th, td { padding: 15px; text-align: left; }
        th { background: #34495e; color: white; }
        tr:nth-child(even) { background: #f8f9fa; }
        tr:hover { background: #ecf0f1; }
        .severity-badge { padding: 5px 12px; border-radius: 20px; font-size: 0.85em; font-weight: bold; }
        .severity-critical { background: #c0392b; color: white; }
        .severity-high { background: #e74c3c; color: white; }
        .severity-medium { background: #f39c12; color: white; }
        .severity-low { background: #3498db; color: white; }
        .severity-info { background: #95a5a6; color: white; }
        .finding-card { background: white; border-radius: 10px; padding: 25px; margin: 20px 0; box-shadow: 0 2px 15px rgba(0,0,0,0.1); border-left: 5px solid; }
        .finding-card.critical { border-left-color: #c0392b; }
        .finding-card.high { border-left-color: #e74c3c; }
        .finding-card.medium { border-left-color: #f39c12; }
        .finding-card.low { border-left-color: #3498db; }
        .finding-card.info { border-left-color: #95a5a6; }
        .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; }
        .finding-title { font-size: 1.2em; font-weight: bold; color: #2c3e50; }
        .recommendation { background: #e8f5e9; padding: 15px; border-radius: 5px; margin-top: 15px; border-left: 4px solid #27ae60; }
        .toc { background: #f8f9fa; padding: 25px; border-radius: 10px; margin-bottom: 40px; }
        .toc h2 { margin-top: 0; border-bottom: none; }
        .toc ul { list-style: none; }
        .toc li { padding: 8px 0; border-bottom: 1px solid #ecf0f1; }
        .toc a { color: #3498db; text-decoration: none; }
        .page-break { page-break-before: always; }
        footer { text-align: center; margin-top: 50px; padding: 30px; background: #34495e; color: white; }
        @media print {
            .cover { height: auto; padding: 100px 0; }
            .page-break { page-break-before: always; }
            .finding-card { break-inside: avoid; }
        }
    </style>
</head>
<body>
    <div class="cover">
        <h1>{{ title }}</h1>
        <p class="subtitle">Security Assessment Report</p>
        <div class="cover-meta">
            <p><strong>Prepared for:</strong> [Client Name]</p>
            <p><strong>Prepared by:</strong> {{ author }}</p>
            <p><strong>Date:</strong> {{ date }}</p>
            <p><strong>Classification:</strong> Confidential</p>
        </div>
    </div>
    
    <div class="container">
        <div class="toc">
            <h2>Table of Contents</h2>
            <ul>
                <li><a href="#executive-summary">1. Executive Summary</a></li>
                <li><a href="#scope">2. Scope and Methodology</a></li>
                <li><a href="#findings-summary">3. Findings Summary</a></li>
                <li><a href="#detailed-findings">4. Detailed Findings</a></li>
                <li><a href="#recommendations">5. Recommendations</a></li>
                <li><a href="#appendix">6. Appendix</a></li>
            </ul>
        </div>
        
        <section id="executive-summary">
            <h2>1. Executive Summary</h2>
            <div class="executive-summary">
                <p>This security assessment was conducted to evaluate the security posture of the target systems. The assessment covered {{ targets|length }} target(s) and identified a total of {{ vulnerabilities|length }} security findings.</p>
                
                <h3>Risk Overview</h3>
                <div class="stats-grid">
                    <div class="stat-box critical">
                        <div class="stat-number">{{ vuln_stats.critical }}</div>
                        <div class="stat-label">Critical</div>
                    </div>
                    <div class="stat-box high">
                        <div class="stat-number">{{ vuln_stats.high }}</div>
                        <div class="stat-label">High</div>
                    </div>
                    <div class="stat-box medium">
                        <div class="stat-number">{{ vuln_stats.medium }}</div>
                        <div class="stat-label">Medium</div>
                    </div>
                    <div class="stat-box low">
                        <div class="stat-number">{{ vuln_stats.low }}</div>
                        <div class="stat-label">Low</div>
                    </div>
                    <div class="stat-box info">
                        <div class="stat-number">{{ vuln_stats.info }}</div>
                        <div class="stat-label">Info</div>
                    </div>
                </div>
                
                <h3>Key Findings</h3>
                <ul>
                    {% if vuln_stats.critical > 0 %}
                    <li><strong>Critical Issues:</strong> {{ vuln_stats.critical }} critical vulnerability(ies) requiring immediate attention</li>
                    {% endif %}
                    {% if vuln_stats.high > 0 %}
                    <li><strong>High Risk Issues:</strong> {{ vuln_stats.high }} high-risk finding(s) that should be addressed promptly</li>
                    {% endif %}
                    <li><strong>Total Targets:</strong> {{ targets|length }} system(s) assessed</li>
                </ul>
            </div>
        </section>
        
        <section id="scope" class="page-break">
            <h2>2. Scope and Methodology</h2>
            
            <h3>2.1 Target Systems</h3>
            <table>
                <tr>
                    <th>ID</th>
                    <th>Type</th>
                    <th>Target</th>
                    <th>Description</th>
                </tr>
                {% for target in targets %}
                <tr>
                    <td>{{ target.id }}</td>
                    <td>{{ target.type|upper }}</td>
                    <td><strong>{{ target.value }}</strong></td>
                    <td>{{ target.description or 'N/A' }}</td>
                </tr>
                {% endfor %}
            </table>
            
            <h3>2.2 Methodology</h3>
            <p>The assessment followed industry-standard penetration testing methodologies including:</p>
            <ul>
                <li>Reconnaissance and Information Gathering</li>
                <li>Vulnerability Scanning and Analysis</li>
                <li>Manual Testing and Validation</li>
                <li>Exploitation Attempts (where authorized)</li>
                <li>Documentation and Reporting</li>
            </ul>
            
            <h3>2.3 Discovered Services</h3>
            {% for target_id, ports in ports_by_target.items() %}
            <h4>Target {{ target_id }}</h4>
            {% if ports %}
            <table>
                <tr>
                    <th>Port</th>
                    <th>Protocol</th>
                    <th>Service</th>
                    <th>Version</th>
                </tr>
                {% for port in ports %}
                <tr>
                    <td><strong>{{ port.port }}</strong></td>
                    <td>{{ port.protocol }}</td>
                    <td>{{ port.service }}</td>
                    <td>{{ port.version or 'Unknown' }}</td>
                </tr>
                {% endfor %}
            </table>
            {% else %}
            <p>No exposed services identified.</p>
            {% endif %}
            {% endfor %}
        </section>
        
        <section id="findings-summary" class="page-break">
            <h2>3. Findings Summary</h2>
            
            {% if vulnerabilities %}
            <table>
                <tr>
                    <th>Severity</th>
                    <th>Finding</th>
                    <th>Location</th>
                </tr>
                {% for vuln in vulnerabilities %}
                <tr>
                    <td><span class="severity-badge severity-{{ vuln.severity }}">{{ vuln.severity|upper }}</span></td>
                    <td>{{ vuln.name }}</td>
                    <td>{{ vuln.location }}</td>
                </tr>
                {% endfor %}
            </table>
            {% else %}
            <p>No significant vulnerabilities were identified during this assessment.</p>
            {% endif %}
        </section>
        
        <section id="detailed-findings" class="page-break">
            <h2>4. Detailed Findings</h2>
            
            {% for vuln in vulnerabilities %}
            <div class="finding-card {{ vuln.severity }}">
                <div class="finding-header">
                    <span class="finding-title">{{ vuln.name }}</span>
                    <span class="severity-badge severity-{{ vuln.severity }}">{{ vuln.severity|upper }}</span>
                </div>
                
                <p><strong>Affected Asset:</strong> {{ vuln.location }}</p>
                <p><strong>Detection Method:</strong> {{ vuln.source }}</p>
                
                {% if vuln.description %}
                <h4>Description</h4>
                <p>{{ vuln.description }}</p>
                {% endif %}
                
                {% if vuln.references %}
                <h4>References</h4>
                <ul>
                    {% for ref in vuln.references[:3] %}
                    <li><a href="{{ ref }}" target="_blank">{{ ref }}</a></li>
                    {% endfor %}
                </ul>
                {% endif %}
                
                <div class="recommendation">
                    <strong>Recommendation:</strong> Review and remediate this vulnerability according to vendor guidelines and security best practices.
                </div>
            </div>
            {% endfor %}
        </section>
        
        <section id="recommendations" class="page-break">
            <h2>5. Recommendations</h2>
            
            <h3>5.1 Immediate Actions (Critical/High)</h3>
            <ul>
                {% if vuln_stats.critical > 0 or vuln_stats.high > 0 %}
                <li>Address all critical and high-severity vulnerabilities within 7 days</li>
                <li>Implement emergency patches where available</li>
                <li>Consider temporary mitigations (WAF rules, network segmentation)</li>
                {% else %}
                <li>No immediate critical actions required</li>
                {% endif %}
            </ul>
            
            <h3>5.2 Short-term Actions (Medium)</h3>
            <ul>
                <li>Remediate medium-severity findings within 30 days</li>
                <li>Review and update security configurations</li>
                <li>Implement security monitoring and alerting</li>
            </ul>
            
            <h3>5.3 Long-term Actions</h3>
            <ul>
                <li>Establish regular vulnerability scanning schedule</li>
                <li>Implement security awareness training</li>
                <li>Review and update security policies</li>
                <li>Consider annual penetration testing</li>
            </ul>
        </section>
        
        <section id="appendix" class="page-break">
            <h2>6. Appendix</h2>
            
            <h3>6.1 Tools Used</h3>
            <ul>
                <li>Nmap - Network scanning and service detection</li>
                <li>Nuclei - Vulnerability scanning</li>
                <li>Gobuster/Feroxbuster - Directory enumeration</li>
                <li>Nikto - Web server scanning</li>
                <li>Various custom scripts and manual testing</li>
            </ul>
            
            <h3>6.2 Testing Timeline</h3>
            <p>Assessment conducted on: {{ date }}</p>
        </section>
    </div>
    
    <footer>
        <p><strong>CONFIDENTIAL</strong> - This document contains sensitive security information</p>
        <p>Generated by HackInterface - {{ date }}</p>
    </footer>
</body>
</html>
"""


# Template Markdown
MARKDOWN_TEMPLATE = """# {{ title }}

**Author:** {{ author }}  
**Date:** {{ date }}  
**Classification:** Confidential

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Scope and Targets](#scope-and-targets)
3. [Findings Summary](#findings-summary)
4. [Detailed Findings](#detailed-findings)
5. [Recommendations](#recommendations)
6. [Appendix](#appendix)

---

## Executive Summary

This security assessment was conducted against **{{ targets|length }}** target(s). The assessment identified **{{ vulnerabilities|length }}** security findings.

### Risk Overview

| Severity | Count |
|----------|-------|
| 🔴 Critical | {{ vuln_stats.critical }} |
| 🟠 High | {{ vuln_stats.high }} |
| 🟡 Medium | {{ vuln_stats.medium }} |
| 🔵 Low | {{ vuln_stats.low }} |
| ⚪ Info | {{ vuln_stats.info }} |

{% if vuln_stats.critical > 0 %}
> ⚠️ **CRITICAL ISSUES DETECTED** - Immediate action required!
{% endif %}

---

## Scope and Targets

### Target Systems

| ID | Type | Target | Description |
|----|------|--------|-------------|
{% for target in targets %}
| {{ target.id }} | {{ target.type }} | `{{ target.value }}` | {{ target.description or 'N/A' }} |
{% endfor %}

### Discovered Services

{% for target_id, ports in ports_by_target.items() %}
#### Target {{ target_id }}

{% if ports %}
| Port | Protocol | Service | Version |
|------|----------|---------|---------|
{% for port in ports %}
| {{ port.port }} | {{ port.protocol }} | {{ port.service }} | {{ port.version or 'Unknown' }} |
{% endfor %}
{% else %}
No open ports discovered.
{% endif %}

{% endfor %}

---

## Findings Summary

{% if vulnerabilities %}
| Severity | Finding | Location |
|----------|---------|----------|
{% for vuln in vulnerabilities %}
| {{ vuln.severity|upper }} | {{ vuln.name }} | {{ vuln.location }} |
{% endfor %}
{% else %}
No significant vulnerabilities were identified during this assessment.
{% endif %}

---

## Detailed Findings

{% for vuln in vulnerabilities %}
### {{ loop.index }}. {{ vuln.name }}

- **Severity:** {{ vuln.severity|upper }}
- **Location:** `{{ vuln.location }}`
- **Detection Method:** {{ vuln.source }}

{% if vuln.description %}
**Description:**
{{ vuln.description }}
{% endif %}

{% if vuln.references %}
**References:**
{% for ref in vuln.references[:3] %}
- {{ ref }}
{% endfor %}
{% endif %}

**Recommendation:** Review and remediate this vulnerability according to vendor guidelines and security best practices.

---

{% endfor %}

## Recommendations

### Immediate Actions (Critical/High)
{% if vuln_stats.critical > 0 or vuln_stats.high > 0 %}
- [ ] Address all critical and high-severity vulnerabilities within 7 days
- [ ] Implement emergency patches where available
- [ ] Consider temporary mitigations (WAF rules, network segmentation)
{% else %}
- [x] No immediate critical actions required
{% endif %}

### Short-term Actions (Medium)
- [ ] Remediate medium-severity findings within 30 days
- [ ] Review and update security configurations
- [ ] Implement security monitoring and alerting

### Long-term Actions
- [ ] Establish regular vulnerability scanning schedule
- [ ] Implement security awareness training
- [ ] Review and update security policies
- [ ] Consider annual penetration testing

---

## Appendix

### Tools Used
- **Nmap** - Network scanning and service detection
- **Nuclei** - Vulnerability scanning
- **Gobuster/Feroxbuster** - Directory enumeration
- **Nikto** - Web server scanning
- **WhatWeb** - Technology fingerprinting

### Assessment Timeline
- **Date:** {{ date }}

---

*Generated by HackInterface*  
*This document contains sensitive security information - handle accordingly.*
"""
