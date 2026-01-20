"""
CCR Context Generator - Generate rich codebase context for LLM security analysis

This module analyzes repositories and generates structured context that can be
passed to LLMs alongside security findings for more accurate analysis.

Copyright (c) 2025 Secuarden 
Licensed under MIT License
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict


@dataclass
class RepoContext:
    """Complete repository context for LLM consumption"""

    architecture: Dict[str, Any]
    entry_points: List[Dict[str, Any]]
    security_posture: Dict[str, Any]
    code_patterns: Dict[str, Any]
    dependencies: Dict[str, Any]
    file_context: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}


class ContextGenerator:
    """
    Generates rich codebase context optimized for LLM security analysis.
    """

    # Security-related packages by ecosystem
    SECURITY_PACKAGES = {
        "python": {
            "auth": ["django-allauth", "flask-login", "passlib", "python-jose", "pyjwt", "authlib", "python-oauth2"],
            "crypto": ["cryptography", "bcrypt", "argon2-cffi", "pynacl", "hashlib"],
            "validation": ["pydantic", "marshmallow", "cerberus", "voluptuous", "wtforms"],
            "security": ["bandit", "safety", "pip-audit", "semgrep"],
            "web_security": ["django-cors-headers", "flask-cors", "secure", "flask-talisman"],
        },
        "javascript": {
            "auth": ["passport", "jsonwebtoken", "jose", "next-auth", "@auth/core", "lucia", "better-auth", "clerk", "auth0"],
            "crypto": ["bcrypt", "bcryptjs", "argon2", "crypto-js", "node-forge"],
            "validation": ["zod", "yup", "joi", "ajv", "class-validator", "superstruct", "valibot"],
            "security": ["helmet", "hpp", "express-rate-limit", "rate-limiter-flexible"],
            "web_security": ["cors", "csurf", "express-session", "cookie-session"],
        },
    }

    # ORM/Database patterns
    ORM_PATTERNS = {
        "prisma": {"files": ["prisma/schema.prisma"], "packages": ["prisma", "@prisma/client"]},
        "drizzle": {"packages": ["drizzle-orm", "drizzle-kit"]},
        "typeorm": {"packages": ["typeorm"]},
        "sequelize": {"packages": ["sequelize"]},
        "mongoose": {"packages": ["mongoose"]},
        "sqlalchemy": {"packages": ["sqlalchemy", "flask-sqlalchemy"]},
        "django_orm": {"files": ["models.py"], "patterns": ["from django.db import models"]},
        "peewee": {"packages": ["peewee"]},
        "tortoise": {"packages": ["tortoise-orm"]},
    }

    # Input validation patterns to search for
    VALIDATION_PATTERNS = {
        "zod_schema": r"z\.(string|number|object|array|boolean)\(",
        "yup_schema": r"yup\.(string|number|object|array|boolean)\(",
        "joi_schema": r"Joi\.(string|number|object|array|boolean)\(",
        "pydantic_model": r"class\s+\w+\(BaseModel\)",
        "class_validator": r"@Is(String|Number|Email|URL|NotEmpty)",
        "express_validator": r"body\(|param\(|query\(",
    }

    # Auth patterns to detect
    AUTH_PATTERNS = {
        "jwt_verify": [r"jwt\.verify", r"jwtVerify", r"verifyToken", r"validateToken"],
        "session_check": [r"req\.session", r"session\.get", r"getSession", r"useSession"],
        "middleware_auth": [r"isAuthenticated", r"requireAuth", r"authMiddleware", r"protect"],
        "oauth_flow": [r"OAuth", r"passport\.authenticate", r"getServerSession"],
        "api_key": [r"x-api-key", r"apiKey", r"API_KEY", r"authorization.*bearer"],
    }

    def __init__(self, repo_path: str):
        """Initialize context generator with repository path."""
        self.repo_path = Path(repo_path)
        if not self.repo_path.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")

        self._package_json_cache = None
        self._requirements_cache = None

    def generate_context(self, target_file: Optional[str] = None) -> RepoContext:
        """
        Generate complete repository context.

        Args:
            target_file: Optional specific file to generate detailed context for

        Returns:
            RepoContext with all analysis results
        """
        context = RepoContext(
            architecture=self._analyze_architecture(),
            entry_points=self._find_entry_points(),
            security_posture=self._analyze_security_posture(),
            code_patterns=self._analyze_code_patterns(),
            dependencies=self._analyze_dependencies(),
        )

        if target_file:
            context.file_context = self._analyze_file_context(target_file)

        return context

    def _analyze_architecture(self) -> Dict[str, Any]:
        """Analyze repository architecture and framework usage."""
        arch = {
            "frameworks": [],
            "languages": [],
            "database": None,
            "auth_system": None,
            "api_style": None,
            "monorepo": False,
            "typescript": False,
        }

        # Detect languages
        lang_extensions = {
            ".py": "Python",
            ".js": "JavaScript",
            ".ts": "TypeScript",
            ".jsx": "JavaScript (React)",
            ".tsx": "TypeScript (React)",
            ".go": "Go",
            ".rs": "Rust",
            ".rb": "Ruby",
            ".java": "Java",
            ".php": "PHP",
        }

        for ext, lang in lang_extensions.items():
            if list(self.repo_path.rglob(f"*{ext}"))[:1]:
                if lang not in arch["languages"]:
                    arch["languages"].append(lang)
                if ext in [".ts", ".tsx"]:
                    arch["typescript"] = True

        # Detect frameworks - check root and workspace packages
        deps = self._get_all_dependencies()

        framework_map = {
            "next": "Next.js",
            "react": "React",
            "vue": "Vue.js",
            "svelte": "Svelte",
            "nuxt": "Nuxt",
            "express": "Express",
            "fastify": "Fastify",
            "hono": "Hono",
            "koa": "Koa",
            "@nestjs/core": "NestJS",
            "better-auth": "Better Auth",
        }

        for pkg_name, framework in framework_map.items():
            if pkg_name in deps:
                arch["frameworks"].append(framework)

        # Python frameworks
        reqs = self._get_requirements()
        py_framework_map = {
            "django": "Django",
            "flask": "Flask",
            "fastapi": "FastAPI",
            "starlette": "Starlette",
        }

        for pkg_name, framework in py_framework_map.items():
            if pkg_name in reqs:
                arch["frameworks"].append(framework)

        # Detect database
        db_indicators = {
            "PostgreSQL": ["pg", "postgres", "@prisma/client", "psycopg2", "asyncpg"],
            "MySQL": ["mysql", "mysql2", "pymysql"],
            "MongoDB": ["mongoose", "mongodb", "pymongo", "motor"],
            "SQLite": ["sqlite3", "better-sqlite3"],
            "Redis": ["redis", "ioredis"],
        }

        for db, packages in db_indicators.items():
            if any(p in deps or p in reqs for p in packages):
                arch["database"] = db
                break

        # Detect auth system
        auth_indicators = {
            "NextAuth.js": ["next-auth", "@auth/core"],
            "Better Auth": ["better-auth"],
            "Passport.js": ["passport"],
            "Lucia": ["lucia"],
            "Clerk": ["@clerk/nextjs", "@clerk/clerk-sdk-node"],
            "Auth0": ["@auth0/nextjs-auth0", "auth0"],
            "Django Auth": ["django.contrib.auth"],
            "Flask-Login": ["flask-login"],
        }

        for auth, packages in auth_indicators.items():
            if any(p in deps or p in reqs for p in packages):
                arch["auth_system"] = auth
                break

        # Detect API style
        if self._directory_exists("app/api") or self._directory_exists("pages/api"):
            arch["api_style"] = "Next.js API Routes"
        elif "trpc" in deps or "@trpc/server" in deps:
            arch["api_style"] = "tRPC"
        elif "graphql" in deps or "@apollo/server" in deps:
            arch["api_style"] = "GraphQL"
        elif "express" in deps or "fastify" in deps or "hono" in deps:
            arch["api_style"] = "REST"

        # Detect monorepo
        if self._directory_exists("packages") or self._directory_exists("apps") or self._file_exists("turbo.json") or self._file_exists("pnpm-workspace.yaml"):
            arch["monorepo"] = True

        return arch

    def _find_entry_points(self) -> List[Dict[str, Any]]:
        """Find and categorize application entry points."""
        entry_points = []

        # API routes
        api_dirs = ["app/api", "pages/api", "src/api", "api", "routes", "src/routes"]
        for api_dir in api_dirs:
            dir_path = self.repo_path / api_dir
            if dir_path.is_dir():
                for route_file in dir_path.rglob("*.ts"):
                    rel_path = route_file.relative_to(self.repo_path)
                    entry_points.append({
                        "type": "api_route",
                        "path": str(rel_path),
                        "methods": self._detect_http_methods(route_file),
                    })
                for route_file in dir_path.rglob("*.js"):
                    rel_path = route_file.relative_to(self.repo_path)
                    entry_points.append({
                        "type": "api_route",
                        "path": str(rel_path),
                        "methods": self._detect_http_methods(route_file),
                    })

        # Express/Fastify route handlers
        for pattern in ["*.routes.ts", "*.routes.js", "*.router.ts", "*.router.js"]:
            for route_file in self.repo_path.rglob(pattern):
                rel_path = route_file.relative_to(self.repo_path)
                entry_points.append({
                    "type": "route_handler",
                    "path": str(rel_path),
                    "methods": self._detect_http_methods(route_file),
                })

        # Python endpoints
        for pattern in ["views.py", "routes.py", "api.py", "endpoints.py"]:
            for py_file in self.repo_path.rglob(pattern):
                rel_path = py_file.relative_to(self.repo_path)
                entry_points.append({
                    "type": "python_endpoint",
                    "path": str(rel_path),
                })

        # Main entry files
        main_files = ["index.ts", "index.js", "main.ts", "main.js", "app.ts", "app.js", "server.ts", "server.js"]
        for main in main_files:
            if self._file_exists(main) or self._file_exists(f"src/{main}"):
                entry_points.append({
                    "type": "main_entry",
                    "path": main if self._file_exists(main) else f"src/{main}",
                })

        return entry_points[:20]  # Limit to avoid overwhelming context

    def _analyze_security_posture(self) -> Dict[str, Any]:
        """Analyze security controls and configurations."""
        posture = {
            "security_packages": [],
            "validation_library": None,
            "auth_library": None,
            "rate_limiting": False,
            "cors_configured": False,
            "helmet_enabled": False,
            "csrf_protection": False,
            "security_headers": False,
            "input_sanitization": False,
            "ci_security_checks": [],
            "security_policy": False,
            "codeowners": False,
        }

        pkg = self._get_package_json()
        deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})} if pkg else {}
        reqs = self._get_requirements()

        # Check for security packages
        for ecosystem, categories in self.SECURITY_PACKAGES.items():
            for category, packages in categories.items():
                for package in packages:
                    if package in deps or package in reqs:
                        posture["security_packages"].append({"name": package, "category": category})

                        # Set specific flags
                        if category == "validation" and not posture["validation_library"]:
                            posture["validation_library"] = package
                        if category == "auth" and not posture["auth_library"]:
                            posture["auth_library"] = package

        # Check specific security controls
        posture["rate_limiting"] = any(p in deps for p in ["express-rate-limit", "rate-limiter-flexible", "@upstash/ratelimit"])
        posture["cors_configured"] = "cors" in deps or self._search_in_files(["*.ts", "*.js"], r"cors\(")
        posture["helmet_enabled"] = "helmet" in deps
        posture["csrf_protection"] = "csurf" in deps or self._search_in_files(["*.ts", "*.js"], r"csrf")

        # Check for security headers in Next.js config
        if self._file_exists("next.config.js") or self._file_exists("next.config.mjs"):
            config_content = self._read_file("next.config.js") or self._read_file("next.config.mjs") or ""
            if "headers" in config_content or "securityHeaders" in config_content:
                posture["security_headers"] = True

        # Check for input sanitization
        posture["input_sanitization"] = any(p in deps for p in ["dompurify", "sanitize-html", "xss", "validator"])

        # Check CI security
        workflow_dir = self.repo_path / ".github" / "workflows"
        if workflow_dir.is_dir():
            for workflow in workflow_dir.glob("*.yml"):
                content = self._read_file(str(workflow.relative_to(self.repo_path))) or ""
                if "snyk" in content.lower():
                    posture["ci_security_checks"].append("Snyk")
                if "semgrep" in content.lower():
                    posture["ci_security_checks"].append("Semgrep")
                if "codeql" in content.lower():
                    posture["ci_security_checks"].append("CodeQL")
                if "dependabot" in content.lower() or "renovate" in content.lower():
                    posture["ci_security_checks"].append("Dependency Updates")

        # Security policy and codeowners
        posture["security_policy"] = self._file_exists("SECURITY.md") or self._file_exists(".github/SECURITY.md")
        posture["codeowners"] = self._file_exists("CODEOWNERS") or self._file_exists(".github/CODEOWNERS")

        return posture

    def _analyze_code_patterns(self) -> Dict[str, Any]:
        """Analyze code patterns related to security."""
        patterns = {
            "orm_usage": None,
            "raw_sql_detected": False,
            "parameterized_queries": False,
            "input_validation_pattern": None,
            "output_encoding": False,
            "error_handling": None,
            "logging_present": False,
            "secrets_management": None,
        }

        pkg = self._get_package_json()
        deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})} if pkg else {}
        reqs = self._get_requirements()

        # Detect ORM
        for orm, config in self.ORM_PATTERNS.items():
            if any(p in deps or p in reqs for p in config.get("packages", [])):
                patterns["orm_usage"] = orm
                patterns["parameterized_queries"] = True  # ORMs use parameterized queries
                break
            for file in config.get("files", []):
                if self._file_exists(file):
                    patterns["orm_usage"] = orm
                    patterns["parameterized_queries"] = True
                    break

        # Check for raw SQL (potential injection risk)
        raw_sql_patterns = [
            r'\.query\s*\(\s*[`"\'].*\$\{',  # Template literal in query
            r'\.raw\s*\(',  # Raw query methods
            r'execute\s*\(\s*f["\']',  # Python f-string in execute
            r'cursor\.execute\s*\(\s*["\'].*%s',  # Python string formatting
        ]
        for pattern in raw_sql_patterns:
            if self._search_in_files(["*.ts", "*.js", "*.py"], pattern):
                patterns["raw_sql_detected"] = True
                break

        # Detect validation pattern
        for name, pattern in self.VALIDATION_PATTERNS.items():
            if self._search_in_files(["*.ts", "*.js", "*.py"], pattern):
                patterns["input_validation_pattern"] = name.replace("_", " ").title()
                break

        # Check for output encoding
        patterns["output_encoding"] = any(p in deps for p in ["dompurify", "he", "escape-html"])

        # Check for structured logging
        logging_libs = ["winston", "pino", "bunyan", "structlog", "loguru"]
        if any(p in deps or p in reqs for p in logging_libs):
            patterns["logging_present"] = True

        # Check secrets management
        secret_managers = {
            "dotenv": ["dotenv", "python-dotenv"],
            "vault": ["node-vault", "hvac"],
            "aws_secrets": ["@aws-sdk/client-secrets-manager", "boto3"],
            "infisical": ["@infisical/sdk"],
        }
        for manager, packages in secret_managers.items():
            if any(p in deps or p in reqs for p in packages):
                patterns["secrets_management"] = manager
                break

        return patterns

    def _analyze_dependencies(self) -> Dict[str, Any]:
        """Analyze dependency information."""
        deps_info = {
            "package_manager": None,
            "lockfile_present": False,
            "total_dependencies": 0,
            "dev_dependencies": 0,
            "security_related": [],
        }

        # Detect package manager and lockfile
        if self._file_exists("pnpm-lock.yaml"):
            deps_info["package_manager"] = "pnpm"
            deps_info["lockfile_present"] = True
        elif self._file_exists("yarn.lock"):
            deps_info["package_manager"] = "yarn"
            deps_info["lockfile_present"] = True
        elif self._file_exists("package-lock.json"):
            deps_info["package_manager"] = "npm"
            deps_info["lockfile_present"] = True
        elif self._file_exists("bun.lockb"):
            deps_info["package_manager"] = "bun"
            deps_info["lockfile_present"] = True
        elif self._file_exists("poetry.lock"):
            deps_info["package_manager"] = "poetry"
            deps_info["lockfile_present"] = True
        elif self._file_exists("Pipfile.lock"):
            deps_info["package_manager"] = "pipenv"
            deps_info["lockfile_present"] = True
        elif self._file_exists("requirements.txt"):
            deps_info["package_manager"] = "pip"

        # Count dependencies
        pkg = self._get_package_json()
        if pkg:
            deps_info["total_dependencies"] = len(pkg.get("dependencies", {}))
            deps_info["dev_dependencies"] = len(pkg.get("devDependencies", {}))

            # Find security-related deps
            all_deps = {**pkg.get("dependencies", {}), **pkg.get("devDependencies", {})}
            security_keywords = ["auth", "security", "crypto", "jwt", "oauth", "session", "helmet", "cors", "csrf", "sanitize", "validate", "zod", "yup"]
            for dep in all_deps:
                if any(kw in dep.lower() for kw in security_keywords):
                    deps_info["security_related"].append(dep)

        return deps_info

    def _analyze_file_context(self, target_file: str) -> Dict[str, Any]:
        """Generate detailed context for a specific file."""
        file_path = self.repo_path / target_file
        if not file_path.exists():
            return {"error": f"File not found: {target_file}"}

        context = {
            "file": target_file,
            "type": self._classify_file(target_file),
            "imports": [],
            "exports": [],
            "functions": [],
            "has_user_input": False,
            "has_database_ops": False,
            "has_auth_checks": False,
            "has_validation": False,
        }

        try:
            content = file_path.read_text(encoding="utf-8")

            # Analyze imports
            import_patterns = [
                r'import\s+.*\s+from\s+["\']([^"\']+)["\']',
                r'require\s*\(["\']([^"\']+)["\']\)',
                r'from\s+(\S+)\s+import',
            ]
            for pattern in import_patterns:
                context["imports"].extend(re.findall(pattern, content))

            # Detect functions
            func_patterns = [
                r'(?:export\s+)?(?:async\s+)?function\s+(\w+)',
                r'(?:export\s+)?const\s+(\w+)\s*=\s*(?:async\s*)?\(',
                r'def\s+(\w+)\s*\(',
            ]
            for pattern in func_patterns:
                context["functions"].extend(re.findall(pattern, content))

            # Check for user input handling
            input_patterns = [r'req\.body', r'req\.params', r'req\.query', r'request\.json', r'request\.form', r'request\.args']
            context["has_user_input"] = any(re.search(p, content) for p in input_patterns)

            # Check for database operations
            db_patterns = [r'\.find', r'\.create', r'\.update', r'\.delete', r'\.query', r'\.execute', r'prisma\.', r'db\.']
            context["has_database_ops"] = any(re.search(p, content) for p in db_patterns)

            # Check for auth checks
            auth_patterns = [r'isAuthenticated', r'requireAuth', r'getSession', r'useSession', r'@login_required', r'auth\.']
            context["has_auth_checks"] = any(re.search(p, content) for p in auth_patterns)

            # Check for validation
            validation_patterns = [r'\.parse\(', r'\.safeParse\(', r'validate\(', r'@IsString', r'@IsEmail', r'BaseModel']
            context["has_validation"] = any(re.search(p, content) for p in validation_patterns)

        except Exception as e:
            context["error"] = str(e)

        return context

    def _classify_file(self, file_path: str) -> str:
        """Classify file type based on path and name."""
        path_lower = file_path.lower()

        if "api" in path_lower or "route" in path_lower:
            return "api_endpoint"
        if "auth" in path_lower:
            return "authentication"
        if "model" in path_lower or "schema" in path_lower:
            return "data_model"
        if "middleware" in path_lower:
            return "middleware"
        if "util" in path_lower or "helper" in path_lower:
            return "utility"
        if "test" in path_lower or "spec" in path_lower:
            return "test"
        if "config" in path_lower:
            return "configuration"

        return "source"

    # Output formatters

    def to_markdown(self, context: RepoContext) -> str:
        """Format context as markdown for LLM consumption."""
        lines = ["# Repository Security Context\n"]

        # Architecture
        arch = context.architecture
        lines.append("## Architecture")
        lines.append(f"- **Languages:** {', '.join(arch['languages']) or 'Not detected'}")
        lines.append(f"- **Frameworks:** {', '.join(arch['frameworks']) or 'None detected'}")
        if arch["database"]:
            lines.append(f"- **Database:** {arch['database']}")
        if arch["auth_system"]:
            lines.append(f"- **Auth System:** {arch['auth_system']}")
        if arch["api_style"]:
            lines.append(f"- **API Style:** {arch['api_style']}")
        lines.append(f"- **TypeScript:** {'Yes' if arch['typescript'] else 'No'}")
        lines.append(f"- **Monorepo:** {'Yes' if arch['monorepo'] else 'No'}")
        lines.append("")

        # Entry Points
        if context.entry_points:
            lines.append("## Entry Points")
            for ep in context.entry_points[:10]:
                methods = f" ({', '.join(ep['methods'])})" if ep.get("methods") else ""
                lines.append(f"- `{ep['path']}`{methods} [{ep['type']}]")
            if len(context.entry_points) > 10:
                lines.append(f"- ... and {len(context.entry_points) - 10} more")
            lines.append("")

        # Security Posture
        posture = context.security_posture
        lines.append("## Security Controls Detected")

        checks = [
            ("CORS configured", posture["cors_configured"]),
            ("Rate limiting", posture["rate_limiting"]),
            ("Helmet (security headers)", posture["helmet_enabled"]),
            ("CSRF protection", posture["csrf_protection"]),
            ("Input sanitization", posture["input_sanitization"]),
            ("Security policy", posture["security_policy"]),
            ("CODEOWNERS", posture["codeowners"]),
        ]

        for label, present in checks:
            mark = "x" if present else " "
            lines.append(f"- [{mark}] {label}")

        if posture["validation_library"]:
            lines.append(f"- [x] Input validation via `{posture['validation_library']}`")
        if posture["auth_library"]:
            lines.append(f"- [x] Authentication via `{posture['auth_library']}`")

        if posture["ci_security_checks"]:
            lines.append(f"- [x] CI security checks: {', '.join(posture['ci_security_checks'])}")
        lines.append("")

        # Code Patterns
        patterns = context.code_patterns
        lines.append("## Code Patterns")
        if patterns["orm_usage"]:
            lines.append(f"- **ORM:** {patterns['orm_usage']} (parameterized queries)")
        if patterns["raw_sql_detected"]:
            lines.append("- **⚠️ Raw SQL detected** - potential injection risk")
        if patterns["input_validation_pattern"]:
            lines.append(f"- **Validation:** {patterns['input_validation_pattern']}")
        if patterns["secrets_management"]:
            lines.append(f"- **Secrets:** {patterns['secrets_management']}")
        if patterns["logging_present"]:
            lines.append("- **Structured logging:** Present")
        lines.append("")

        # Dependencies
        deps = context.dependencies
        lines.append("## Dependencies")
        lines.append(f"- **Package Manager:** {deps['package_manager'] or 'Unknown'}")
        lines.append(f"- **Lockfile:** {'Present' if deps['lockfile_present'] else 'Missing'}")
        lines.append(f"- **Total:** {deps['total_dependencies']} production, {deps['dev_dependencies']} dev")
        if deps["security_related"]:
            lines.append(f"- **Security-related:** {', '.join(deps['security_related'][:5])}")
        lines.append("")

        # File-specific context
        if context.file_context and "error" not in context.file_context:
            fc = context.file_context
            lines.append(f"## File Context: `{fc['file']}`")
            lines.append(f"- **Type:** {fc['type']}")
            lines.append(f"- **Functions:** {', '.join(fc['functions'][:5]) or 'None detected'}")
            lines.append(f"- **User input handling:** {'Yes' if fc['has_user_input'] else 'No'}")
            lines.append(f"- **Database operations:** {'Yes' if fc['has_database_ops'] else 'No'}")
            lines.append(f"- **Auth checks:** {'Yes' if fc['has_auth_checks'] else 'No'}")
            lines.append(f"- **Input validation:** {'Yes' if fc['has_validation'] else 'No'}")
            lines.append("")

        return "\n".join(lines)

    def to_json(self, context: RepoContext) -> str:
        """Format context as JSON."""
        return json.dumps(context.to_dict(), indent=2)

    def to_xml(self, context: RepoContext) -> str:
        """Format context as XML (Claude's preferred format for structured data)."""
        lines = ["<repo_context>"]

        # Architecture
        arch = context.architecture
        lines.append("  <architecture>")
        lines.append(f"    <languages>{', '.join(arch['languages'])}</languages>")
        lines.append(f"    <frameworks>{', '.join(arch['frameworks'])}</frameworks>")
        if arch["database"]:
            lines.append(f"    <database>{arch['database']}</database>")
        if arch["auth_system"]:
            lines.append(f"    <auth_system>{arch['auth_system']}</auth_system>")
        if arch["api_style"]:
            lines.append(f"    <api_style>{arch['api_style']}</api_style>")
        lines.append(f"    <typescript>{str(arch['typescript']).lower()}</typescript>")
        lines.append(f"    <monorepo>{str(arch['monorepo']).lower()}</monorepo>")
        lines.append("  </architecture>")

        # Entry Points
        lines.append("  <entry_points>")
        for ep in context.entry_points[:10]:
            methods = f" methods=\"{','.join(ep['methods'])}\"" if ep.get("methods") else ""
            lines.append(f"    <endpoint type=\"{ep['type']}\"{methods}>{ep['path']}</endpoint>")
        lines.append("  </entry_points>")

        # Security Posture
        posture = context.security_posture
        lines.append("  <security_posture>")
        lines.append(f"    <cors_configured>{str(posture['cors_configured']).lower()}</cors_configured>")
        lines.append(f"    <rate_limiting>{str(posture['rate_limiting']).lower()}</rate_limiting>")
        lines.append(f"    <helmet_enabled>{str(posture['helmet_enabled']).lower()}</helmet_enabled>")
        lines.append(f"    <csrf_protection>{str(posture['csrf_protection']).lower()}</csrf_protection>")
        if posture["validation_library"]:
            lines.append(f"    <validation_library>{posture['validation_library']}</validation_library>")
        if posture["auth_library"]:
            lines.append(f"    <auth_library>{posture['auth_library']}</auth_library>")
        if posture["ci_security_checks"]:
            lines.append(f"    <ci_security_checks>{', '.join(posture['ci_security_checks'])}</ci_security_checks>")
        lines.append("  </security_posture>")

        # Code Patterns
        patterns = context.code_patterns
        lines.append("  <code_patterns>")
        if patterns["orm_usage"]:
            lines.append(f"    <orm>{patterns['orm_usage']}</orm>")
        lines.append(f"    <raw_sql_detected>{str(patterns['raw_sql_detected']).lower()}</raw_sql_detected>")
        lines.append(f"    <parameterized_queries>{str(patterns['parameterized_queries']).lower()}</parameterized_queries>")
        if patterns["input_validation_pattern"]:
            lines.append(f"    <validation_pattern>{patterns['input_validation_pattern']}</validation_pattern>")
        if patterns["secrets_management"]:
            lines.append(f"    <secrets_management>{patterns['secrets_management']}</secrets_management>")
        lines.append("  </code_patterns>")

        # File context if present
        if context.file_context and "error" not in context.file_context:
            fc = context.file_context
            lines.append(f"  <file_context file=\"{fc['file']}\" type=\"{fc['type']}\">")
            lines.append(f"    <has_user_input>{str(fc['has_user_input']).lower()}</has_user_input>")
            lines.append(f"    <has_database_ops>{str(fc['has_database_ops']).lower()}</has_database_ops>")
            lines.append(f"    <has_auth_checks>{str(fc['has_auth_checks']).lower()}</has_auth_checks>")
            lines.append(f"    <has_validation>{str(fc['has_validation']).lower()}</has_validation>")
            lines.append("  </file_context>")

        lines.append("</repo_context>")
        return "\n".join(lines)

    # Helper methods

    def _get_package_json(self) -> Dict[str, Any]:
        """Get and cache package.json contents."""
        if self._package_json_cache is not None:
            return self._package_json_cache

        pkg_path = self.repo_path / "package.json"
        if pkg_path.exists():
            try:
                self._package_json_cache = json.loads(pkg_path.read_text(encoding="utf-8"))
            except:
                self._package_json_cache = {}
        else:
            self._package_json_cache = {}

        return self._package_json_cache

    def _get_requirements(self) -> set:
        """Get Python requirements as a set of package names."""
        if self._requirements_cache is not None:
            return self._requirements_cache

        requirements = set()

        # Check requirements.txt
        req_path = self.repo_path / "requirements.txt"
        if req_path.exists():
            try:
                for line in req_path.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        # Extract package name (before ==, >=, etc.)
                        pkg = re.split(r'[=<>!\[]', line)[0].strip().lower()
                        if pkg:
                            requirements.add(pkg)
            except:
                pass

        # Check pyproject.toml
        pyproject_path = self.repo_path / "pyproject.toml"
        if pyproject_path.exists():
            try:
                content = pyproject_path.read_text(encoding="utf-8").lower()
                # Simple extraction - look for common package names
                common_pkgs = ["django", "flask", "fastapi", "sqlalchemy", "pydantic", "pytest"]
                for pkg in common_pkgs:
                    if pkg in content:
                        requirements.add(pkg)
            except:
                pass

        self._requirements_cache = requirements
        return self._requirements_cache

    def _get_all_dependencies(self) -> set:
        """Get all dependencies from root and workspace packages."""
        all_deps = set()

        # Get from root package.json
        pkg = self._get_package_json()
        if pkg:
            all_deps.update(pkg.get("dependencies", {}).keys())
            all_deps.update(pkg.get("devDependencies", {}).keys())

        # Check for workspace packages (monorepo)
        workspace_dirs = ["packages", "apps"]
        for ws_dir in workspace_dirs:
            ws_path = self.repo_path / ws_dir
            if ws_path.is_dir():
                # Find all package.json files in workspace
                for pkg_file in ws_path.rglob("package.json"):
                    try:
                        pkg_data = json.loads(pkg_file.read_text(encoding="utf-8"))
                        all_deps.update(pkg_data.get("dependencies", {}).keys())
                        all_deps.update(pkg_data.get("devDependencies", {}).keys())
                        all_deps.update(pkg_data.get("peerDependencies", {}).keys())
                    except:
                        pass

        return all_deps

    def _file_exists(self, filename: str) -> bool:
        """Check if file exists in repo."""
        return (self.repo_path / filename).exists()

    def _directory_exists(self, dirname: str) -> bool:
        """Check if directory exists in repo."""
        return (self.repo_path / dirname).is_dir()

    def _read_file(self, filename: str) -> Optional[str]:
        """Read file contents safely."""
        try:
            return (self.repo_path / filename).read_text(encoding="utf-8")
        except:
            return None

    def _search_in_files(self, patterns: List[str], regex: str) -> bool:
        """Search for regex pattern in files matching glob patterns."""
        compiled = re.compile(regex)
        for pattern in patterns:
            for file_path in list(self.repo_path.rglob(pattern))[:50]:  # Limit search
                try:
                    content = file_path.read_text(encoding="utf-8")
                    if compiled.search(content):
                        return True
                except:
                    pass
        return False

    def _detect_http_methods(self, file_path: Path) -> List[str]:
        """Detect HTTP methods used in a route file."""
        methods = []
        try:
            content = file_path.read_text(encoding="utf-8")
            method_patterns = {
                "GET": [r'\.get\(', r'GET', r'@get', r'export.*GET'],
                "POST": [r'\.post\(', r'POST', r'@post', r'export.*POST'],
                "PUT": [r'\.put\(', r'PUT', r'@put', r'export.*PUT'],
                "PATCH": [r'\.patch\(', r'PATCH', r'@patch', r'export.*PATCH'],
                "DELETE": [r'\.delete\(', r'DELETE', r'@delete', r'export.*DELETE'],
            }
            for method, patterns in method_patterns.items():
                if any(re.search(p, content, re.IGNORECASE) for p in patterns):
                    methods.append(method)
        except:
            pass
        return methods
