import win32file
import win32api

class USBManager:
    def __init__(self):
        self.connected_drives = self.get_usb_drives()

    def get_usb_drives(self):
        """
        Retrieve all currently connected removable USB drives.

        Returns:
            set: A set of drive letters (e.g., {'E:\\', 'F:\\'}) for all removable drives detected.
        """
        drives = win32api.GetLogicalDriveStrings().split('\000')[:-1]
        usb_drives = set()
        for drive in drives:
            if win32file.GetDriveType(drive) == win32file.DRIVE_REMOVABLE:
                usb_drives.add(drive)
        return usb_drives

    def update_drives(self, usb_list):
        """
        Update the provided USB drive list with changes in connected removable drives.

        Args:
            usb_list (set): A set representing the current USB drives list to update.

        Returns:
            set: The updated set with added and removed drives reflected.

        Side Effects:
            Updates the internal `connected_drives` attribute to the current state.
        """
        current_drives = self.get_usb_drives()
        added = current_drives - self.connected_drives
        removed = self.connected_drives - current_drives

        for d in added:
            usb_list.add(d)

        for d in removed:
            usb_list.discard(d)

        self.connected_drives = current_drives
        return usb_list
