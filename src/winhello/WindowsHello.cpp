/*
 *  Copyright (C) 2022 KeePassXC Team <team@keepassxc.org>
 *  Copyright (C) 2022 Thomas Hobson (HexF) <thomas@hexf.me>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "WindowsHello.h"

#include <QApplication>
#include <QCoreApplication>
#include <QHash>
#include <QWidget>

#include <windows.h>

#ifndef MS_NGC_KEY_STORAGE_PROVIDER
#define MS_NGC_KEY_STORAGE_PROVIDER L"Microsoft Passport Key Storage Provider" // MinGW doesn't provide this
#endif
#ifndef NCRYPT_PIN_CACHE_IS_GESTURE_REQUIRED_PROPERTY
#define NCRYPT_PIN_CACHE_IS_GESTURE_REQUIRED_PROPERTY L"PinCacheIsGestureRequired"
#endif

using namespace WindowsHello;

namespace
{
    QHash<QString, QByteArray> g_encryptedMasterKeys;

    int g_winHelloAvailable = WINDOWSHELLO_UNDEFINED;

    bool getNCryptHandles(NCRYPT_PROV_HANDLE* hProv, NCRYPT_KEY_HANDLE* hKey)
    {
        if (NCryptOpenStorageProvider(hProv, MS_NGC_KEY_STORAGE_PROVIDER, 0) != ERROR_SUCCESS) {
            g_winHelloAvailable = WINDOWSHELLO_NOT_AVAILABLE;
            return false;
        }

        NCryptKeyName* keyname = nullptr;
        PVOID pos = nullptr;

        // There is either 0 or 1 keys in here - we need to get the name so we just enumerate the store.
        // If we get an error, its empty and can exit
        if (NCryptEnumKeys(*hProv, NULL, &keyname, &pos, 0) != ERROR_SUCCESS) {
            g_winHelloAvailable = WINDOWSHELLO_NOT_AVAILABLE;
            return false;
        }

        if (NCryptOpenKey(*hProv, hKey, keyname->pszName, keyname->dwLegacyKeySpec, 0) != ERROR_SUCCESS) {
            NCryptFreeBuffer(keyname);

            g_winHelloAvailable = WINDOWSHELLO_NOT_AVAILABLE;
            return false;
        }

        NCryptFreeBuffer(keyname);

        QString promptMessage =
            QCoreApplication::translate("DatabaseOpenDialog", "authenticate to access the database");
        wchar_t* prompt = new wchar_t[promptMessage.length() * 2];
        promptMessage.toWCharArray(prompt);

        if (NCryptSetProperty(*hKey,
                              NCRYPT_USE_CONTEXT_PROPERTY,
                              reinterpret_cast<PBYTE>(prompt),
                              (promptMessage.length() + 1) * 2,
                              0)
            != ERROR_SUCCESS) {

            g_winHelloAvailable = WINDOWSHELLO_NOT_AVAILABLE;
            return false;
        }

        QWidget* activeWindow = QApplication::activeWindow();
        if (activeWindow != nullptr) {
            WId windowHandle = activeWindow->winId();

            if (NCryptSetProperty(*hKey,
                                  NCRYPT_WINDOW_HANDLE_PROPERTY,
                                  reinterpret_cast<PBYTE>(&windowHandle),
                                  sizeof(windowHandle),
                                  0)
                != ERROR_SUCCESS) {

                g_winHelloAvailable = WINDOWSHELLO_NOT_AVAILABLE;
                return false;
            }
        }

        DWORD requirePin = 1;

        if (NCryptSetProperty(
                *hKey, NCRYPT_PIN_CACHE_IS_GESTURE_REQUIRED_PROPERTY, reinterpret_cast<PBYTE>(&requirePin), 4, 0)
            != ERROR_SUCCESS) {

            g_winHelloAvailable = WINDOWSHELLO_NOT_AVAILABLE;
            return false;
        }

        g_winHelloAvailable = WINDOWSHELLO_AVAILABLE;
        return true;
    }

    void freeNCryptHandles(NCRYPT_PROV_HANDLE* hProv, NCRYPT_KEY_HANDLE* hKey)
    {
        NCryptFreeObject(*hKey);
        NCryptFreeObject(*hProv);
    }
} // namespace

bool WindowsHello::isAvailable()
{
    if (g_winHelloAvailable == WINDOWSHELLO_UNDEFINED) {
        NCRYPT_PROV_HANDLE hProvider;
        NCRYPT_KEY_HANDLE hKey;

        getNCryptHandles(&hProvider, &hKey);
        freeNCryptHandles(&hProvider, &hKey);
    }

    return g_winHelloAvailable == WINDOWSHELLO_AVAILABLE;
}

bool WindowsHello::storeKey(const QString& databasePath, const QByteArray& passwordKey)
{
    if (databasePath.isEmpty() || passwordKey.isEmpty() || !isAvailable()) {
        return false;
    }

    if (g_encryptedMasterKeys.contains(databasePath)) {
        return true;
    }

    NCRYPT_PROV_HANDLE hProvider;
    NCRYPT_KEY_HANDLE hKey;

    if (!getNCryptHandles(&hProvider, &hKey)) {
        freeNCryptHandles(&hProvider, &hKey);
        return false;
    }

    DWORD encryptedLength = -1;
    PBYTE passwordData = const_cast<PBYTE>(reinterpret_cast<const BYTE*>(passwordKey.data()));

    if (NCryptEncrypt(hKey, passwordData, passwordKey.length(), NULL, NULL, 0, &encryptedLength, NCRYPT_PAD_PKCS1_FLAG)
        != ERROR_SUCCESS) {
        freeNCryptHandles(&hProvider, &hKey);
        return false;
    }

    PBYTE cipherData = new BYTE[encryptedLength];

    if (NCryptEncrypt(hKey,
                      passwordData,
                      passwordKey.length(),
                      NULL,
                      cipherData,
                      encryptedLength,
                      &encryptedLength,
                      NCRYPT_PAD_PKCS1_FLAG)
        != ERROR_SUCCESS) {
        freeNCryptHandles(&hProvider, &hKey);
        return false;
    }

    g_encryptedMasterKeys.insert(databasePath,
                                 {reinterpret_cast<const char*>(cipherData), static_cast<int>(encryptedLength)});

    freeNCryptHandles(&hProvider, &hKey);
    return true;
}

bool WindowsHello::getKey(const QString& databasePath, QByteArray& passwordKey)
{
    if (databasePath.isEmpty() || !hasKey(databasePath) || !isAvailable()) {
        return false;
    }

    NCRYPT_PROV_HANDLE hProvider;
    NCRYPT_KEY_HANDLE hKey;

    if (!getNCryptHandles(&hProvider, &hKey)) {
        freeNCryptHandles(&hProvider, &hKey);
        return false;
    }

    QByteArray encryptedMasterKey = g_encryptedMasterKeys[databasePath];
    PBYTE masterKeyBytes = const_cast<PBYTE>(reinterpret_cast<const BYTE*>(encryptedMasterKey.data()));
    DWORD masterKeyBytesLength = -1;

    if (NCryptDecrypt(hKey,
                      masterKeyBytes,
                      encryptedMasterKey.length(),
                      NULL,
                      masterKeyBytes,
                      encryptedMasterKey.length(),
                      &masterKeyBytesLength,
                      NCRYPT_PAD_PKCS1_FLAG)
        != ERROR_SUCCESS) {
        freeNCryptHandles(&hProvider, &hKey);
        return false;
    }

    passwordKey = QByteArray(reinterpret_cast<const char*>(masterKeyBytes), static_cast<int>(masterKeyBytesLength));

    freeNCryptHandles(&hProvider, &hKey);
    return true;
}

bool WindowsHello::hasKey(const QString& databasePath)
{
    return g_encryptedMasterKeys.contains(databasePath);
}

void WindowsHello::reset(const QString& databasePath)
{
    if (databasePath.isEmpty()) {
        g_encryptedMasterKeys.clear();
    } else {
        g_encryptedMasterKeys.remove(databasePath);
    }
}
