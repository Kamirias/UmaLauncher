import os
import subprocess
import util
from loguru import logger
import vpn
import dmm_session
import gui

_progress_dialog = None

def start(use_direct_launch=True, threader=None):
    global _progress_dialog
    
    if use_direct_launch:
        logger.info("Trying to launch Uma Musume directly")
        
        def update_progress(status, progress=0, filepath=""):
            global _progress_dialog
            
            if status == "checking":
                if not _progress_dialog and threader:
                    threader.widget_queue.append((gui.UmaUpdateProgressDialog, [], {}))
                
                logger.info(f"Checking files: {int(progress * 100)}%")
                if _progress_dialog:
                    _progress_dialog.queue_update("checking", progress)
            elif status == "downloading":
                if not _progress_dialog and threader:
                    threader.widget_queue.append((gui.UmaUpdateProgressDialog, [], {}))
                    import time
                    timeout = time.time() + 2
                    while not _progress_dialog:
                        time.sleep(0.05)
                        if gui.APPLICATION and gui.APPLICATION.main_widget:
                            _progress_dialog = gui.APPLICATION.main_widget
                        if time.time() > timeout:
                            break
                
                if filepath:
                    logger.info(f"Downloading: {int(progress * 100)}% - {filepath}")
                else:
                    logger.info(f"Downloading update: {int(progress * 100)}%")
                if _progress_dialog:
                    _progress_dialog.queue_update("downloading", progress, filepath)
            elif status == "complete":
                logger.info("Game update completed")
                if _progress_dialog:
                    _progress_dialog.queue_update("complete")
                    import time
                    time.sleep(1)
                    _progress_dialog.close()
                    _progress_dialog = None
        
        launch_info = dmm_session.get_launch_info(update_callback=update_progress)
        
        if not launch_info:
            logger.warning("Failed to get launch info from DMM API, launching via DMM instead.")
            os.system("Start dmmgameplayer://play/GCL/umamusume/cl/win")
            return
        
        if launch_info.get("area_restricted"):
            logger.error("Game launch cancelled due to region restriction")
            if threader:
                threader.stop()
            return
        
        game_path = launch_info["game_path"]
        exec_file = launch_info["exec_file"]
        args = launch_info["args"]
        
        full_path = os.path.join(game_path, exec_file)
        
        logger.info(f"Launching game: {full_path}")
        redacted_args = [arg if not any(x in arg for x in ['token', 'access']) else arg.split('=')[0] + '=[REDACTED]' for arg in args]
        logger.debug(f"Args: {redacted_args}")
        
        try:
            subprocess.Popen([full_path] + args, cwd=game_path, creationflags=subprocess.CREATE_NO_WINDOW)
            logger.info("Game launched successfully")
        except Exception as e:
            logger.error(f"Failed to launch game: {e}")
            logger.warning("Falling back to protocol handler")
            os.system("Start dmmgameplayer://play/GCL/umamusume/cl/win")
    else:
        logger.info("Launching Uma Musume via DMM.")
        os.system("Start dmmgameplayer://play/GCL/umamusume/cl/win")

def get_dmm_handle():
    dmm_handle = util.get_window_handle("DMMGamePlayer.exe", type=util.EXEC_MATCH)
    if dmm_handle:
        return dmm_handle
    return None