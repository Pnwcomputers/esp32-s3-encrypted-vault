package com.pnwcomputers.vault;

import android.Manifest;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.AlertDialog;
import android.bluetooth.*;
import android.bluetooth.le.*;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelUuid;
import android.os.SystemClock;
import android.text.InputType;
import android.view.View;
import android.view.WindowManager;
import android.widget.*;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@SuppressLint("MissingPermission") // All GATT and scan work follows the runtime permission check.
public final class MainActivity extends Activity {
    private static final UUID SERVICE = uuid("0");
    private static final UUID COMMAND = uuid("1");
    private static final UUID STATUS = uuid("2");
    private static final String[] PERMISSIONS = {
        Manifest.permission.BLUETOOTH_SCAN, Manifest.permission.BLUETOOTH_CONNECT
    };
    private static final String[] RESULTS = {
        "No unlock request received.",
        "Unlocking…",
        "USB export ready. Check the computer for the drive.",
        "Incorrect vault PIN.",
        "Too many attempts. Wait before trying again.",
        "Create the USB drive in the vault web interface first.",
        "Could not open the vault or export the drive. Check the SD card and USB settings.",
        "Safely eject the drive on the computer before changing write protection."
    };

    private final Handler ui = new Handler(Looper.getMainLooper());
    private final Map<String, BluetoothDevice> found = new LinkedHashMap<>();
    private BluetoothLeScanner scanner;
    private ScanCallback scan;
    private BluetoothGatt gatt;
    private BluetoothGattCharacteristic command;
    private BluetoothGattCharacteristic result;
    private TextView status;
    private Button scanButton;
    private Button unlockButton;
    private EditText pin;
    private CheckBox readOnly;
    private boolean verifiedPairing;
    private int mtu = 23;
    private long deadline;

    private static UUID uuid(String suffix) {
        return UUID.fromString("399c100" + suffix + "-bc55-482d-a8a2-5fe1776146a1");
    }

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        getWindow().addFlags(WindowManager.LayoutParams.FLAG_SECURE);
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        int pad = Math.round(24 * getResources().getDisplayMetrics().density);
        layout.setPadding(pad, pad, pad, pad);
        layout.setOnApplyWindowInsetsListener((view, insets) -> {
            var edges = insets.getInsets(android.view.WindowInsets.Type.systemBars());
            view.setPadding(pad + edges.left, pad + edges.top, pad + edges.right, pad + edges.bottom);
            return insets;
        });
        scanButton = new Button(this);
        scanButton.setText("Find vault");
        scanButton.setOnClickListener(view -> startScan());
        status = new TextView(this);
        status.setAccessibilityLiveRegion(View.ACCESSIBILITY_LIVE_REGION_POLITE);
        status.setText("Plug the vault into the computer, then find it over Bluetooth.");
        pin = new EditText(this);
        pin.setSingleLine();
        pin.setHint("Vault PIN or passphrase");
        pin.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        pin.setSaveEnabled(false);
        pin.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO);
        pin.setEnabled(false);
        readOnly = new CheckBox(this);
        readOnly.setText("Write-protect USB drive");
        readOnly.setChecked(true);
        unlockButton = new Button(this);
        unlockButton.setText("Unlock and mount USB");
        unlockButton.setEnabled(false);
        unlockButton.setOnClickListener(view -> unlock());
        layout.addView(status);
        layout.addView(scanButton);
        layout.addView(pin);
        layout.addView(readOnly);
        layout.addView(unlockButton);
        ScrollView scroll = new ScrollView(this);
        scroll.addView(layout);
        setContentView(scroll);
        if (Build.VERSION.SDK_INT_FULL < Build.VERSION_CODES_FULL.BAKLAVA_1) {
            status.setText("Bluetooth unlock requires Android 16 QPR2 or later.");
            scanButton.setEnabled(false);
        }
    }

    private boolean hasPermissions() {
        return Arrays.stream(PERMISSIONS).allMatch(p ->
                checkSelfPermission(p) == PackageManager.PERMISSION_GRANTED);
    }

    private void startScan() {
        if (!hasPermissions()) {
            requestPermissions(PERMISSIONS, 1);
            return;
        }
        closeConnection();
        BluetoothAdapter adapter = getSystemService(BluetoothManager.class).getAdapter();
        if (adapter == null || !adapter.isEnabled()
                || (scanner = adapter.getBluetoothLeScanner()) == null) {
            status.setText("Turn on Bluetooth and try again.");
            return;
        }
        found.clear();
        scanButton.setEnabled(false);
        status.setText("Looking for nearby vaults…");
        ScanCallback callback = new ScanCallback() {
            @Override public void onScanResult(int type, ScanResult item) {
                ui.post(() -> {
                    if (scan != this) return;
                    BluetoothDevice device = item.getDevice();
                    found.put(device.getAddress(), device);
                });
            }

            @Override public void onScanFailed(int error) {
                ui.post(() -> {
                    if (scan == this) fail("Bluetooth scan failed (" + error + ").");
                });
            }
        };
        scan = callback;
        scanner.startScan(List.of(new ScanFilter.Builder()
                        .setServiceUuid(new ParcelUuid(SERVICE)).build()),
                new ScanSettings.Builder().setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY).build(),
                callback);
        ui.postDelayed(() -> {
            if (scan != callback) return;
            stopScan();
            scanButton.setEnabled(true);
            if (found.isEmpty()) {
                status.setText("No vault found. Check that it is powered and try again.");
                return;
            }
            BluetoothDevice[] devices = found.values().toArray(new BluetoothDevice[0]);
            String[] names = Arrays.stream(devices).map(device -> "ESP32 Vault · "
                    + device.getAddress()
                    + (device.getBondState() == BluetoothDevice.BOND_BONDED ? " (paired)" : ""))
                    .toArray(String[]::new);
            status.setText("Select your vault. For a new pairing, use the code on its LCD.");
            new AlertDialog.Builder(this).setTitle("Select vault")
                    .setItems(names, (dialog, index) -> connect(devices[index]))
                    .setNegativeButton("Cancel", null).show();
        }, 3500);
    }

    @Override public void onRequestPermissionsResult(int request, String[] permissions, int[] grants) {
        super.onRequestPermissionsResult(request, permissions, grants);
        if (request == 1 && hasPermissions()) startScan();
        else if (request == 1) status.setText("Allow Nearby devices to find and unlock the vault.");
    }

    private void connect(BluetoothDevice device) {
        closeConnection();
        mtu = 23;
        String address = device.getAddress();
        if (device.getBondState() != BluetoothDevice.BOND_BONDED) {
            getPreferences(MODE_PRIVATE).edit().remove(address).apply();
        }
        verifiedPairing = getPreferences(MODE_PRIVATE).getBoolean(address, false);
        status.setText("Connecting. If Android asks, enter the Bluetooth code shown on the vault LCD.");
        gatt = device.connectGatt(this, false, callbacks, BluetoothDevice.TRANSPORT_LE);
        if (gatt == null) {
            fail("Could not start the Bluetooth connection.");
            return;
        }
        BluetoothGatt link = gatt;
        deadline = SystemClock.elapsedRealtime() + 45_000;
        long pairingDeadline = deadline;
        ui.postDelayed(() -> {
            if (gatt == link && deadline == pairingDeadline && !pin.isEnabled())
                fail("Connection or pairing timed out.");
        }, 45_000);
    }

    private final BluetoothGattCallback callbacks = new BluetoothGattCallback() {
        @Override public void onConnectionStateChange(BluetoothGatt link, int code, int state) {
            ui.post(() -> {
                if (link != gatt) return;
                if (code != BluetoothGatt.GATT_SUCCESS || state == BluetoothProfile.STATE_DISCONNECTED) {
                    fail("Vault disconnected. Find it again to reconnect.");
                } else if (state == BluetoothProfile.STATE_CONNECTED && !link.discoverServices()) {
                    fail("Could not discover the vault service.");
                }
            });
        }

        @Override public void onServicesDiscovered(BluetoothGatt link, int code) {
            ui.post(() -> {
                if (link != gatt) return;
                BluetoothGattService service = link.getService(SERVICE);
                if (code != BluetoothGatt.GATT_SUCCESS || service == null
                        || (command = service.getCharacteristic(COMMAND)) == null
                        || (result = service.getCharacteristic(STATUS)) == null) {
                    fail("This firmware does not expose the vault unlock service.");
                } else if (!link.requestMtu(128)) {
                    fail("Could not negotiate Bluetooth packet size.");
                }
            });
        }

        @Override public void onMtuChanged(BluetoothGatt link, int size, int code) {
            ui.post(() -> {
                if (link != gatt) return;
                if (code != BluetoothGatt.GATT_SUCCESS || size < 67) {
                    fail("Bluetooth packet size is too small for this firmware.");
                    return;
                }
                mtu = size;
                waitForSecureLink(link);
            });
        }

        @Override public void onCharacteristicWrite(BluetoothGatt link,
                BluetoothGattCharacteristic characteristic, int code) {
            ui.post(() -> {
                if (link != gatt || !COMMAND.equals(characteristic.getUuid())) return;
                if (code == BluetoothGatt.GATT_SUCCESS) readResult(link);
                else finishRequest("The vault rejected the Bluetooth request. Try again.");
            });
        }

        @Override public void onCharacteristicRead(BluetoothGatt link,
                BluetoothGattCharacteristic characteristic, byte[] value, int code) {
            int state = value.length == 1 ? Byte.toUnsignedInt(value[0]) : -1;
            ui.post(() -> {
                if (link != gatt || !STATUS.equals(characteristic.getUuid())) return;
                if (code != BluetoothGatt.GATT_SUCCESS || state < 0 || state >= RESULTS.length) {
                    fail("Could not verify the vault status.");
                } else if (state == 1) {
                    ui.postDelayed(() -> readResult(link), 250);
                } else {
                    finishRequest(RESULTS[state]);
                }
            });
        }
    };

    private boolean secure(BluetoothGatt link) {
        BluetoothDevice device = link.getDevice();
        if (device.getBondState() != BluetoothDevice.BOND_BONDED) return false;
        EncryptionStatus encryption = device.getEncryptionStatus(BluetoothDevice.TRANSPORT_LE);
        return encryption != null && encryption.getKeySize() == 16
                && encryption.getAlgorithm() == BluetoothDevice.ENCRYPTION_ALGORITHM_AES;
    }

    private void waitForSecureLink(BluetoothGatt link) {
        if (link != gatt) return;
        if (secure(link)) {
            if (verifiedPairing) showPinEntry();
            else confirmLcdPairing(link);
        } else if (SystemClock.elapsedRealtime() < deadline)
            ui.postDelayed(() -> waitForSecureLink(link), 250);
        else fail("Android could not verify an encrypted Bluetooth link.");
    }

    private void confirmLcdPairing(BluetoothGatt link) {
        new AlertDialog.Builder(this)
                .setTitle("Verify the vault pairing")
                .setMessage("Continue only if you entered the six-digit code shown on your vault LCD into Android’s pairing prompt.")
                .setPositiveButton("I entered the LCD code", (dialog, which) -> {
                    if (gatt != link || !secure(link)) return;
                    verifiedPairing = true;
                    getPreferences(MODE_PRIVATE).edit()
                            .putBoolean(link.getDevice().getAddress(), true).apply();
                    showPinEntry();
                })
                .setNegativeButton("Disconnect", (dialog, which) -> fail("Vault pairing was not verified."))
                .setOnCancelListener(dialog -> fail("Vault pairing was not verified."))
                .show();
    }

    private void showPinEntry() {
        finishRequest("Paired and encrypted. Enter the vault PIN to mount USB.");
    }

    private void unlock() {
        BluetoothGatt link = gatt;
        if (link == null || !verifiedPairing || !secure(link)) {
            fail("The encrypted Bluetooth link is unavailable. Reconnect.");
            return;
        }
        if (pin.length() < 1 || pin.length() > 63) {
            status.setText("Enter a vault PIN or passphrase of 1–63 UTF-8 bytes.");
            return;
        }
        char[] characters = new char[pin.length()];
        pin.getText().getChars(0, characters.length, characters, 0);
        ByteBuffer encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(characters));
        Arrays.fill(characters, '\0');
        int length = encoded.remaining();
        if (length > 63 || length + 4 > mtu) {
            Arrays.fill(encoded.array(), (byte) 0);
            status.setText("The vault PIN or passphrase exceeds 63 UTF-8 bytes.");
            return;
        }
        byte[] request = new byte[length + 1];
        request[0] = (byte) (readOnly.isChecked() ? 1 : 0);
        encoded.get(request, 1, length);
        Arrays.fill(encoded.array(), (byte) 0);
        pin.getText().clear();
        pin.setEnabled(false);
        unlockButton.setEnabled(false);
        status.setText("Unlocking…");
        deadline = SystemClock.elapsedRealtime() + 30_000;
        try {
            if (link.writeCharacteristic(command, request, BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT)
                    != BluetoothStatusCodes.SUCCESS) {
                finishRequest("Could not send the unlock request.");
                return;
            }
        } finally {
            Arrays.fill(request, (byte) 0);
        }
        long requestDeadline = deadline;
        ui.postDelayed(() -> {
            if (gatt == link && requestDeadline == deadline && !pin.isEnabled())
                fail("No result from the vault. Check the computer before retrying.");
        }, 30_000);
    }

    private void readResult(BluetoothGatt link) {
        if (link != gatt) return;
        if (SystemClock.elapsedRealtime() >= deadline || !secure(link) || !link.readCharacteristic(result))
            fail("Could not read the unlock result. Check the computer before retrying.");
    }

    private void finishRequest(String feedback) {
        status.setText(feedback);
        pin.setEnabled(true);
        unlockButton.setEnabled(true);
    }

    private void fail(String feedback) {
        stopScan();
        closeConnection();
        scanButton.setEnabled(true);
        status.setText(feedback);
    }

    private void stopScan() {
        if (scan != null && hasPermissions()) scanner.stopScan(scan);
        scan = null;
    }

    private void closeConnection() {
        BluetoothGatt link = gatt;
        gatt = null;
        verifiedPairing = false;
        if (link != null) link.close();
        pin.getText().clear();
        pin.setEnabled(false);
        unlockButton.setEnabled(false);
    }

    @Override protected void onDestroy() {
        stopScan();
        closeConnection();
        ui.removeCallbacksAndMessages(null);
        super.onDestroy();
    }
}
