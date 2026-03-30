from PySide6.QtWidgets import QApplication
import sys
from ui.dashboard import DashboardScreen
from core.event_bus import event_bus
from core.usb_monitor import USBEventEmitter
import time
from PySide6.QtCore import QTimer

app = QApplication(sys.argv)

monitor = USBEventEmitter()
monitor.start()

dashboard = DashboardScreen()
dashboard.resize(1024, 768)
dashboard.show()

print('Dashboard launched — check for animated stats, particles, gauge, and threat badges')
print('Waiting 20 seconds for fake USB events to update the timeline...')

start_time = time.time()
while time.time() - start_time < 20:
    app.processEvents()
    time.sleep(0.05)

monitor.stop()
print('Test finished. Close the window when done.')
QTimer.singleShot(500, app.quit)
sys.exit(app.exec())
