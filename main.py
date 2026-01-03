import uasyncio
from led_touch import listen
print("NEW")
uasyncio.run(listen())
