import {useEffect, useState} from "react";
import {invoke} from "@tauri-apps/api/core";
import {listen} from '@tauri-apps/api/event'
import {open} from "@tauri-apps/plugin-dialog";
import { openUrl } from '@tauri-apps/plugin-opener';
import "./App.css";

interface AppState {
    disableStart: boolean;
    hidePassword: boolean;
    inpath: string;
    isLargeFile: boolean;
    keypath: string;
    mode: string;
    outpath: string;
    password: string;
    passwordMatch: boolean;
    passwordRepeated: string;
    requirePassword: boolean;
    requirePasswordRepeated: boolean;
    showMatchingIcon: boolean;
    showVisibilityIcon: boolean;
    statusErr: string;
    statusOk: string;
}

const initialState: AppState = {
    disableStart: true,
    hidePassword: true,
    inpath: "",
    isLargeFile: false,
    keypath: "",
    mode: "se",
    outpath: "",
    password: "",
    passwordMatch: false,
    passwordRepeated: "",
    requirePassword: true,
    requirePasswordRepeated: true,
    showMatchingIcon: false,
    showVisibilityIcon: true,
    statusErr: "",
    statusOk: "Ready",
};

function App() {
    const [state, setState] = useState(initialState);

    const updateState = (stateChanges: Partial<AppState>) => {
        setState(prevState => ({
            ...prevState,
            ...stateChanges,
        }));
    };

    listen<string>('tauri://drag-drop', (event: any) => {
        let inputPath = event.payload.paths[0];
        let inputDirPath = inputPath.replace(/[/\\][^/\\]*$/, '');

        updateState({
            inpath: inputPath,
            outpath: inputDirPath,
            statusOk: "Ready",
        });
    }).then();

    useEffect(() => {
        const {hidePassword, inpath, password, passwordRepeated, requirePasswordRepeated, keypath} = state;

        // Modes:
        // se == symmetric encryption, sd == symmetric decryption, he == hybrid encryption, hd == hybrid decryption, gk == generate a key pair

        if (inpath.endsWith(".fcr")) {
            invoke<string>("detect_mode", {inpath}).then((detected) => {
                if (detected) {
                    updateState({mode: detected})
                }
            });
        }

        switch (mode) {
            case "se": { // Symmetric encryption mode
                updateState({
                    disableStart: inpath === "" || password.length < 1 || (password !== passwordRepeated && requirePasswordRepeated),
                    requirePassword: true,
                    requirePasswordRepeated: hidePassword,
                    showMatchingIcon: hidePassword ? !!passwordRepeated : false,
                    showVisibilityIcon: true,
                });
            }
                break;
            case "sd": { // Symmetric decryption mode
                updateState({
                    disableStart: inpath === "" || password.length < 1,
                    requirePassword: true,
                    requirePasswordRepeated: false,
                    showMatchingIcon: false,
                    showVisibilityIcon: true,
                });
            }
                break;
            case "he": { // Hybrid encryption mode
                updateState({
                    disableStart: inpath === "" || keypath === "",
                    requirePassword: false,
                    requirePasswordRepeated: false,
                    showMatchingIcon: false,
                    showVisibilityIcon: false,
                });
            }
                break;
            case "hd": { // Hybrid decryption mode
                updateState({
                    disableStart: inpath === "" || password.length < 1 || keypath === "",
                    requirePasswordRepeated: false,
                    showMatchingIcon: false,
                    showVisibilityIcon: true,
                });
            }
                break;
            case "gk": { // Generate key pair mode
                updateState({
                    disableStart: outpath === "" || password.length < 1 || (password !== passwordRepeated && requirePasswordRepeated),
                    requirePassword: true,
                    requirePasswordRepeated: hidePassword,
                    showMatchingIcon: hidePassword ? !!passwordRepeated : false,
                    showVisibilityIcon: true,
                });
            }
        }
    }, [
        state.hidePassword,
        state.inpath,
        state.keypath,
        state.mode,
        state.outpath,
        state.password,
        state.passwordRepeated,
        state.requirePassword,
        state.requirePasswordRepeated,
    ]);


    const handleSelectKey = async () => {
        const selected = await open({
            multiple: false,
            directory: false
        }) as string;

        updateState({
            keypath: selected
        });
    };

    const handleSelectOutputDir = async () => {
        const selected = await open({
            multiple: false,
            directory: true
        }) as string;

        updateState({
            outpath: selected
        });
    };

    const handlePasswordChange = (value: string) => {
        updateState({
            password: value
        });
    }

    const handleRepeatedPasswordChange = (value: string) => {
        updateState({
            passwordRepeated: value
        });
    }

    const handleLargeFileSupport = () => {
        updateState({
            isLargeFile: !state.isLargeFile
        });
    }

    const handleSymmetricEncryptionMode = () => {
        updateState({
            mode: "se"
        });
    }

    const handleHybridEncryptionMode = () => {
        updateState({
            mode: "he"
        });
    }

    const handleGenerateKeyPairMode = () => {
        updateState({
            mode: "gk"
        });
    }

    const handlePasswordHide = () => {
        updateState({
            hidePassword: !state.hidePassword
        });
    }

    const handleStart = async () => {
        updateState({
            statusOk: "Working ...",
            statusErr: "",
        });

        const {inpath, outpath, password, isLargeFile, keypath, mode} = state;

        await invoke("start", {
            inpath,
            outpath,
            password,
            isLargeFile,
            keypath,
            mode
        })
            // @ts-ignore
            .then((message: string) => {
                handleClear();

                updateState({
                    statusOk: message,
                    statusErr: "",
                });
            })
            .catch((error: string) => {
                updateState({
                    statusOk: "",
                    statusErr: error.replace(/"+/g, ''),
                });
            });
    }

    const handleClear = () => setState(initialState);

    const handleExternalLink = async (e: { preventDefault: () => void; }) => {
        e.preventDefault();
        await openUrl('https://github.com/alexylon/Ferrocrypt');
    }


    const {
        disableStart,
        hidePassword,
        inpath,
        isLargeFile,
        keypath,
        mode,
        outpath,
        password,
        passwordRepeated,
        requirePassword,
        requirePasswordRepeated,
        showMatchingIcon,
        showVisibilityIcon,
        statusErr,
        statusOk,
    } = state;

    return (
        <div className="container">
            <div className="row">
                <div className="link" onClick={handleExternalLink}>
                    <img src="/padlock-red-256.png" className="logo ferrocrypt" alt="Ferrocrypt logo"/>
                </div>
            </div>
            <div>
                <div className={`helper ${mode !== "gk" ? '' : 'disabled'}`}>Drop a file or folder into app
                    window
                </div>
                <div className="row">
                    <input
                        id="inpath"
                        disabled={true}
                        value={mode === "gk" ? "" : state.inpath}
                        style={{marginRight: 10, width: "100%"}}
                    />
                    <button onClick={handleClear} style={{width: "90px"}}>Clear</button>
                </div>
                <div className="cbx-form">
                    <label htmlFor="rdo1">
                        <input
                            type="radio"
                            id="rdo1"
                            name="radio"
                            onChange={handleSymmetricEncryptionMode}
                            checked={mode === "se" || mode === "sd"}
                            disabled={mode === "hd"}
                        />
                        <span className="rdo"></span>
                        <span className="rdo-label">Symmetric</span>
                    </label>
                    <span className="spacer-15"/>
                    <label htmlFor="rdo2">
                        <input
                            type="radio"
                            id="rdo2"
                            name="radio"
                            onChange={handleHybridEncryptionMode}
                            checked={mode === "he" || mode === "hd"}
                            disabled={mode === "sd"}
                        />
                        <span className="rdo"></span>
                        <span className="rdo-label">Hybrid</span>
                    </label>
                    <span className="spacer-15"/>
                    <label htmlFor="rdo3">
                        <input
                            type="radio"
                            id="rdo3"
                            name="radio"
                            onChange={handleGenerateKeyPairMode}
                            checked={mode === "gk"}
                            disabled={mode === "sd" || mode === "hd" || (mode !== "gk" && inpath !== "")}
                        />
                        <span className="rdo"></span>
                        <span className="rdo-label">Create key pair</span>
                    </label>
                </div>
                <label className={`helper ${requirePassword ? '' : 'disabled'}`}>Password:</label>
                <div className="row">
                    <input
                        id="password-input"
                        type={hidePassword ? "password" : "text"}
                        value={requirePassword ? password : ""}
                        disabled={!requirePassword}
                        onChange={(e) => handlePasswordChange(e.currentTarget.value)}
                        placeholder={requirePassword ? "Enter a password..." : ""}
                        style={{width: "100%"}}
                    />
                    <div className="visibility-icon">
                        {showVisibilityIcon &&
                            <img
                                src={hidePassword ? "/icon-unhide-50.png" : "/icon-hide-50.png"}
                                alt="visibility icon"
                                style={{width: "20px"}}
                                onClick={handlePasswordHide}
                            ></img>
                        }
                    </div>
                </div>
                <div className="row">
                    <input
                        id="repeat-password-input"
                        type="password"
                        value={requirePasswordRepeated ? passwordRepeated : ""}
                        disabled={!requirePasswordRepeated}
                        onChange={(e) => handleRepeatedPasswordChange(e.currentTarget.value)}
                        placeholder={requirePasswordRepeated ? "Repeat the password..." : ""}
                        style={{width: "100%"}}
                    />
                    <div className="match-icon">
                        {showMatchingIcon &&
                            <img
                                src={hidePassword && !!passwordRepeated && password === passwordRepeated
                                    ? "/icon-dot-green-30.png"
                                    : "/icon-dot-red-30.png"}
                                alt="match icon"
                                style={{width: "20px"}}
                            ></img>
                        }
                    </div>
                </div>
                <label className={`helper ${mode === "se" || mode === "sd" || mode === "gk" ? 'disabled' : ''}`}>Key (PEM format):</label>
                <div className="row">
                    <input
                        id="key"
                        disabled={true}
                        value={keypath}
                        placeholder={mode === "he" ? "Select a public key..." : mode === "hd" ? "Select your private key..." : ""}
                        style={{marginRight: 10, width: "100%"}}
                    />
                    <button
                        onClick={handleSelectKey}
                        disabled={mode === "se" || mode === "sd" || mode === "gk"}
                        style={{width: "90px"}}
                    >Select
                    </button>
                </div>
                <div className="cbx-form">
                    <label htmlFor="checkbox1">
                        <input type="checkbox"
                               id="checkbox1"
                               checked={isLargeFile}
                               onChange={handleLargeFileSupport}
                               disabled={mode === "sd" || mode === "he" || mode === "hd" || mode === "gk"}
                        />
                        <span className="cbx">
                            <svg width="12px" height="11px" viewBox="0 0 12 11">
                                {mode === "sd" || mode === "he" || mode === "hd" || mode === "gk"
                                    ? ""
                                    : <polyline points="1 6.29411765 4.5 10 11 1"/>}
                            </svg>
                        </span>
                        <span className="cbx-label">Large files (low RAM usage)</span>
                    </label>
                </div>
                <div className="helper">Save output to this folder:</div>
                <div className="row">
                    <input
                        id="outpath"
                        disabled={true}
                        value={outpath}
                        style={{marginRight: 10, width: "100%"}}
                    />
                    <button onClick={handleSelectOutputDir} style={{width: "90px"}}>Select</button>
                </div>
                <hr className="solid"/>
                <div className="row">
                    <form
                        onSubmit={(e) => {
                            e.preventDefault();
                            handleStart().then();
                        }}
                    >
                        <button
                            type="submit"
                            style={{width: "350px"}}
                            disabled={disableStart}
                        >{mode === "se" || mode === "he" ? "Encrypt" : mode === "sd" || mode === "hd" ? "Decrypt" : "Create key pair"}
                        </button>
                    </form>
                </div>
                <div className="helper" style={{color: "darkseagreen"}}>{statusOk}</div>
                <div className="helper" style={{color: "#C41E3A"}}> {statusErr} </div>
            </div>
        </div>
    )
        ;
}

export default App;
