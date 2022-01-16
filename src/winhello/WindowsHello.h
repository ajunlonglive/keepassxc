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

#ifndef KEEPASSX_WINDOWSHELLO_H
#define KEEPASSX_WINDOWSHELLO_H

#define WINDOWSHELLO_UNDEFINED -1
#define WINDOWSHELLO_AVAILABLE 1
#define WINDOWSHELLO_NOT_AVAILABLE 0

#include <QString>

namespace WindowsHello
{
    bool storeKey(const QString& databasePath, const QByteArray& passwordKey);

    bool getKey(const QString& databasePath, QByteArray& passwordKey);

    bool hasKey(const QString& databasePath);

    bool isAvailable();

    void reset(const QString& databasePath = "");
} // namespace WindowsHello

#endif // KEEPASSX_WINDOWSHELLO_H
