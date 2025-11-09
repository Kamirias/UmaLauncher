import os
import subprocess
import util
from loguru import logger
import vpn
import dmm_session

def start(use_direct_launch=True):
    if use_direct_launch:
        logger.info("Trying to launch Uma Musume directly")
        
        launch_info = dmm_session.get_launch_info()
        
        if not launch_info:
            logger.warning("Failed to get launch info from DMM API, launching via DMM instead.")
            os.system("Start dmmgameplayer://play/GCL/umamusume/cl/win")
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