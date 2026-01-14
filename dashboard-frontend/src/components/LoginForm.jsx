import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Eye, EyeOff, User, Lock } from "lucide-react";
import "./LoginForm.css";
import MonImage from "../images/LOGO.png";
import { useAuth } from "../hooks/useAuth";
import BrandedLoader from "../components/BrandedLoader"; // Import du composant

export default function LoginForm() {
    const navigate = useNavigate();
    const { login } = useAuth(); // Utiliser useAuth correctement
    
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [showPassword, setShowPassword] = useState(false);
    const [isLoading, setIsLoading] = useState(false);
    const [errors, setErrors] = useState({});

    const handleSubmit = async () => {
        setIsLoading(true);
        setErrors({});

        // Validation
        const newErrors = {};
        if (!username.trim()) newErrors.username = "Nom d'utilisateur requis";
        if (!password) newErrors.password = "Mot de passe requis";

        if (Object.keys(newErrors).length > 0) {
            setErrors(newErrors);
            setIsLoading(false);
            return;
        }

        // Appel à la fonction login du hook useAuth
        const result = await login(username, password);

        if (result.success) {
            setUsername("");
            setPassword("");
            navigate("/dashboard");
        } else {
            setErrors({ general: result.message || "Identifiants incorrects" });
        }

        setIsLoading(false);
    };

    const handleKeyPress = (e) => {
        if (e.key === "Enter") {
            handleSubmit();
        }
    };

    return (
        <div className="login-container">
            {/* Overlay de loading avec BrandedLoader */}
            {isLoading && <BrandedLoader />}

            <div className="background-effects">
                <div className="bg-circle bg-circle-1"></div>
                <div className="bg-circle bg-circle-2"></div>
            </div>

            <div className="login-wrapper">
                <div className="login-card">
                    <div className="login-header">
                        <div className="logo-container">
                            <div className="logo-placeholder">
                                <img src={MonImage} alt="CFAO Mobility Cameroon Logo" style={{ width: "190px", height: "auto" }} />
                            </div>
                        </div>
                        <h2 className="login-title">Connexion</h2>
                        <p className="login-subtitle">Accédez à votre espace professionnel</p>
                    </div>

                    {errors.general && <div className="error-message">{errors.general}</div>}

                    <div className="login-form">
                        <div className="form-group">
                            <label className="form-label">Identifiant</label>
                            <div className="input-container">
                                <div className="input-icon">
                                    <User className="icon" />
                                </div>
                                <input
                                    type="text"
                                    value={username}
                                    onChange={(e) => setUsername(e.target.value)}
                                    onKeyPress={handleKeyPress}
                                    className={`form-input ${errors.username ? "input-error" : ""}`}
                                    placeholder="Entrez votre nom d'utilisateur"
                                    disabled={isLoading}
                                />
                            </div>
                            {errors.username && <p className="field-error">{errors.username}</p>}
                        </div>

                        <div className="form-group">
                            <label className="form-label">Mot de passe</label>
                            <div className="input-container">
                                <div className="input-icon">
                                    <Lock className="icon" />
                                </div>
                                <input
                                    type={showPassword ? "text" : "password"}
                                    value={password}
                                    onChange={(e) => setPassword(e.target.value)}
                                    onKeyPress={handleKeyPress}
                                    className={`form-input password-input ${errors.password ? "input-error" : ""}`}
                                    placeholder="Entrez votre mot de passe"
                                    disabled={isLoading}
                                />
                                <button
                                    type="button"
                                    onClick={() => setShowPassword(!showPassword)}
                                    className="password-toggle"
                                    disabled={isLoading}
                                >
                                    {showPassword ? <EyeOff className="icon" /> : <Eye className="icon" />}
                                </button>
                            </div>
                            {errors.password && <p className="field-error">{errors.password}</p>}
                        </div>

                        <button 
                            onClick={handleSubmit} 
                            disabled={isLoading} 
                            className="submit-button"
                        >
                            Se connecter
                        </button>
                    </div>

                    <div className="login-footer">
                        <a href="#" className="forgot-password">
                            Mot de passe oublié ?
                        </a>
                    </div>
                </div>

                <div className="copyright">
                    <p>© 2025 CFAO Mobility Cameroon. Tous droits réservés.</p>
                </div>
            </div>
        </div>
    );
}