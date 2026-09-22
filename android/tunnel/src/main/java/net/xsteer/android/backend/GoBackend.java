/*
 * Copyright © 2017-2025 WireGuard LLC. All Rights Reserved.
 * Copyright © 2026 xsteer.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Взято из клиента WireGuard под Android и переделано: наружу остался тот же Backend, внутри
 * вместо wireguard-go работает половина xsteer на Go.
 *
 * ЧТО ИМЕННО ЗАМЕНЕНО. Там движок жил нативной библиотекой и звался через JNI (wgTurnOn,
 * wgTurnOff, wgGetConfig), а настройка уезжала в него строкой uapi. Здесь движок приезжает
 * готовым xsteer.aar (gomobile), настройка уезжает текстом в том же виде, в каком её читает
 * консольная половина, а состояние возвращается снимком JSON. Точка стыка та же самая и
 * единственная: система строит туннель и отдаёт дескриптор, дальше им распоряжается Go.
 *
 * ЧЕГО ЗДЕСЬ НЕТ по сравнению с исходником: protect() сокетов движка. У нас их не достать — они
 * заводятся внутри Go, — поэтому из туннеля исключается САМО ПРИЛОЖЕНИЕ. Следствие то же: путь к
 * хабу не заворачивается в туннель, которого ещё нет.
 */

package net.xsteer.android.backend;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.net.ConnectivityManager;
import android.net.Network;
import android.os.PowerManager;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.os.SystemClock;
import android.system.OsConstants;
import android.util.Log;

import net.xsteer.android.backend.BackendException.Reason;
import net.xsteer.android.backend.Tunnel.State;
import net.xsteer.config.Config;
import net.xsteer.config.InetEndpoint;
import net.xsteer.config.InetNetwork;
import net.xsteer.config.Peer;
import net.xsteer.crypto.Key;
import net.xsteer.crypto.KeyFormatException;
import net.xsteer.util.NonNullForAll;

import org.json.JSONException;
import org.json.JSONObject;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.util.Collections;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import androidx.annotation.Nullable;
import androidx.collection.ArraySet;

/**
 * Реализация {@link Backend} поверх половины xsteer на Go.
 */
@NonNullForAll
public final class GoBackend implements Backend {
    private static final int DNS_RESOLUTION_RETRIES = 10;
    private static final String TAG = "xsteer/Backend";
    // Пробуждение приходит несколькими извещениями подряд (экран, разблокировка, выход из
    // дремоты); переподнимать соединения на каждое — рвать только что поднятые.
    private static final long WAKE_GAP_MS = 2000;
    @Nullable private static AlwaysOnCallback alwaysOnCallback;
    private static CompletableFuture<VpnService> vpnService = new CompletableFuture<>();
    private final Context context;
    @Nullable private Config currentConfig;
    @Nullable private Tunnel currentTunnel;
    // volatile: пишется при подъёме и снятии (поток вызывающего setState), а читается из
    // обратных вызовов сети и приёмника пробуждения — у них свои потоки.
    @Nullable private volatile xsteer.Tunnel goTunnel;
    @Nullable private ConnectivityManager.NetworkCallback netCallback;
    @Nullable private BroadcastReceiver wakeReceiver;

    public GoBackend(final Context context) {
        this.context = context;
    }

    /**
     * Обратный вызов на случай, когда службу подняла сама система в режиме «всегда включён».
     */
    public static void setAlwaysOnCallback(final AlwaysOnCallback cb) {
        alwaysOnCallback = cb;
    }

    @Override
    public Set<String> getRunningTunnelNames() {
        if (currentTunnel != null) {
            final Set<String> runningTunnels = new ArraySet<>();
            runningTunnels.add(currentTunnel.getName());
            return runningTunnels;
        }
        return Collections.emptySet();
    }

    @Override
    public State getState(final Tunnel tunnel) {
        return currentTunnel == tunnel ? State.UP : State.DOWN;
    }

    /**
     * Счётчики туннеля.
     *
     * У xsteer они общие на весь туннель, а не по пирам: в звезде у пира ровно один собеседник —
     * хаб. Поэтому вся строка счётчиков приписывается его ключу, и выглядит это на экране так же,
     * как у туннеля с единственным пиром.
     */
    @Override
    public Statistics getStatistics(final Tunnel tunnel) {
        final Statistics stats = new Statistics();
        final xsteer.Tunnel go = goTunnel;
        final Config config = currentConfig;
        if (tunnel != currentTunnel || go == null || config == null || config.getPeers().isEmpty())
            return stats;
        try {
            final JSONObject o = new JSONObject(go.stateJSON());
            final Key key = config.getPeers().get(0).getPublicKey();
            final long age = o.optLong("handshake_age", -1);
            // handshake_age — возраст последнего рукопожатия в секундах; экран ждёт момент
            // времени. Отрицательный возраст означает «рукопожатия не было», и момент тогда ноль:
            // так же, как у исходника, где ноль означал «поля нет».
            final long handshake = age >= 0 ? System.currentTimeMillis() - age * 1000 : 0;
            stats.add(key, o.optLong("rx_bytes"), o.optLong("tx_bytes"), handshake);
        } catch (final JSONException e) {
            Log.w(TAG, "снимок состояния не разобрался: " + e.getMessage());
        }
        return stats;
    }

    @Override
    public String getVersion() {
        return xsteer.Xsteer.version();
    }

    @Override
    public boolean isAlwaysOn() throws ExecutionException, InterruptedException, TimeoutException {
        return vpnService.get(0, TimeUnit.NANOSECONDS).isAlwaysOn();
    }

    @Override
    public boolean isLockdownEnabled() throws ExecutionException, InterruptedException, TimeoutException {
        return vpnService.get(0, TimeUnit.NANOSECONDS).isLockdownEnabled();
    }

    @Override
    public State setState(final Tunnel tunnel, State state, @Nullable final Config config) throws Exception {
        final State originalState = getState(tunnel);

        if (state == State.TOGGLE)
            state = originalState == State.UP ? State.DOWN : State.UP;
        if (state == originalState && tunnel == currentTunnel && config == currentConfig)
            return originalState;
        if (state == State.UP) {
            final Config originalConfig = currentConfig;
            final Tunnel originalTunnel = currentTunnel;
            if (currentTunnel != null)
                setStateInternal(currentTunnel, null, State.DOWN);
            try {
                setStateInternal(tunnel, config, state);
            } catch (final Exception e) {
                if (originalTunnel != null)
                    setStateInternal(originalTunnel, originalConfig, State.UP);
                throw e;
            }
        } else if (state == State.DOWN && tunnel == currentTunnel) {
            setStateInternal(tunnel, null, State.DOWN);
        }
        return getState(tunnel);
    }

    /**
     * Настройка для половины на Go — тем же текстом, что читает консольная половина.
     *
     * СОБИРАЕТСЯ ЗДЕСЬ, А НЕ БЕРЁТСЯ ГОТОВОЙ. У модели настройки из приложения есть ключи,
     * которых движок не знает (PresharedKey, ListenPort, FwMark, списки приложений), и строгий
     * разбор отверг бы их целиком. Поэтому пишем ровно то, что движок принимает, и ничего сверх.
     */
    private static String xsteerConfig(final Config config) throws BackendException {
        final StringBuilder sb = new StringBuilder();
        sb.append("[Interface]\n");
        sb.append("PrivateKey = ").append(config.getInterface().getKeyPair().getPrivateKey().toBase64()).append('\n');
        for (final InetNetwork addr : config.getInterface().getAddresses()) {
            // Адрес внутри туннеля у xsteer только IPv4: движок разбирает адреса как четыре байта
            // и шестого семейства не знает вовсе. Молча выбросить адрес нельзя — туннель поднялся
            // бы без него и не нёс бы обратного трафика, — поэтому отказ с объяснением.
            if (addr.getAddress() instanceof Inet6Address)
                throw new BackendException(Reason.CONFIG_NOT_ACCEPTED,
                        "адрес " + addr + ": xsteer работает только с IPv4");
            sb.append("Address = ").append(addr).append('\n');
        }
        final StringBuilder dns = new StringBuilder();
        for (final InetAddress addr : config.getInterface().getDnsServers()) {
            if (addr instanceof Inet6Address)
                continue;
            if (dns.length() > 0)
                dns.append(", ");
            dns.append(addr.getHostAddress());
        }
        if (dns.length() > 0)
            sb.append("DNS = ").append(dns).append('\n');
        if (config.getInterface().getMtu().isPresent())
            sb.append("MTU = ").append(config.getInterface().getMtu().get()).append('\n');
        final String sni = config.getInterface().getSni().orElse("");
        if (!sni.isEmpty())
            sb.append("SNI = ").append(sni).append('\n');

        if (config.getPeers().size() != 1)
            throw new BackendException(Reason.CONFIG_NOT_ACCEPTED,
                    "пиров " + config.getPeers().size() + ": у звезды xsteer он ровно один — хаб");
        final Peer peer = config.getPeers().get(0);
        sb.append("\n[Peer]\n");
        sb.append("PublicKey = ").append(peer.getPublicKey().toBase64()).append('\n');
        final StringBuilder allowed = new StringBuilder();
        for (final InetNetwork net : peer.getAllowedIps()) {
            if (net.getAddress() instanceof Inet6Address)
                continue;
            if (allowed.length() > 0)
                allowed.append(", ");
            allowed.append(net);
        }
        if (allowed.length() == 0)
            throw new BackendException(Reason.CONFIG_NOT_ACCEPTED, "в AllowedIPs нет ни одной сети IPv4");
        sb.append("AllowedIPs = ").append(allowed).append('\n');
        final InetEndpoint ep = peer.getEndpoint().orElse(null);
        if (ep == null)
            throw new BackendException(Reason.CONFIG_NOT_ACCEPTED, "у хаба не указан Endpoint");
        // Endpoint отдаётся УЖЕ РАЗРЕШЁННЫМ: движок принимает только литерал адреса, потому что
        // разрешение имени само может пойти в этот же туннель. Разрешает его цикл ниже, до
        // подъёма, пока старая маршрутизация ещё цела.
        final InetEndpoint resolved = ep.getResolved().orElse(ep);
        sb.append("Endpoint = ").append(resolved.getHost()).append(':').append(resolved.getPort()).append('\n');
        if (peer.getPersistentKeepalive().isPresent())
            sb.append("PersistentKeepalive = ").append(peer.getPersistentKeepalive().get()).append('\n');
        return sb.toString();
    }

    private void setStateInternal(final Tunnel tunnel, @Nullable final Config config, final State state)
            throws Exception {
        Log.i(TAG, "туннель " + tunnel.getName() + ": " + state);

        if (state == State.UP) {
            if (config == null)
                throw new BackendException(Reason.TUNNEL_MISSING_CONFIG);

            if (VpnService.prepare(context) != null)
                throw new BackendException(Reason.VPN_NOT_AUTHORIZED);

            final VpnService service;
            if (!vpnService.isDone()) {
                Log.d(TAG, "прошу систему поднять службу");
                context.startService(new Intent(context, VpnService.class));
            }

            try {
                service = vpnService.get(2, TimeUnit.SECONDS);
            } catch (final TimeoutException e) {
                final Exception be = new BackendException(Reason.UNABLE_TO_START_VPN);
                be.initCause(e);
                throw be;
            }
            service.setOwner(this);

            if (goTunnel != null) {
                Log.w(TAG, "туннель уже поднят");
                return;
            }

            dnsRetry: for (int i = 0; i < DNS_RESOLUTION_RETRIES; ++i) {
                // Имя хаба разрешается ДО подъёма, пока прежняя маршрутизация цела.
                for (final Peer peer : config.getPeers()) {
                    final InetEndpoint ep = peer.getEndpoint().orElse(null);
                    if (ep == null)
                        continue;
                    if (ep.getResolved().orElse(null) == null) {
                        if (i < DNS_RESOLUTION_RETRIES - 1) {
                            Log.w(TAG, "имя \"" + ep.getHost() + "\" не разрешилось, пробую ещё");
                            Thread.sleep(1000);
                            continue dnsRetry;
                        } else
                            throw new BackendException(Reason.DNS_RESOLUTION_FAILURE, ep.getHost());
                    }
                }
                break;
            }

            final xsteer.Tunnel go = xsteer.Xsteer.newTunnel();
            go.setLogger(line -> Log.i(TAG, line == null ? "" : line));
            try {
                go.configure(xsteerConfig(config));
            } catch (final BackendException e) {
                throw e;
            } catch (final Exception e) {
                throw new BackendException(Reason.CONFIG_NOT_ACCEPTED, e.getMessage() == null ? "" : e.getMessage());
            }

            final VpnService.Builder builder = service.getBuilder();
            builder.setSession(tunnel.getName());

            boolean includesApps = false;
            for (final String includedApplication : config.getInterface().getIncludedApplications()) {
                builder.addAllowedApplication(includedApplication);
                includesApps = true;
            }
            for (final String excludedApplication : config.getInterface().getExcludedApplications())
                builder.addDisallowedApplication(excludedApplication);

            // СЕБЯ ИЗ ТУННЕЛЯ ИСКЛЮЧАЕМ — иначе соединение к хабу ушло бы в туннель, которого ещё
            // нет, и подъём упёрся бы в таймаут. Только когда список «кого пускать» пуст: в нём
            // нас и так нет, а смешивать два списка система не разрешает.
            if (!includesApps) {
                try {
                    builder.addDisallowedApplication(context.getPackageName());
                } catch (final Exception e) {
                    Log.w(TAG, "не вышло исключить себя из туннеля: " + e.getMessage());
                }
            }

            for (final InetNetwork addr : config.getInterface().getAddresses())
                builder.addAddress(addr.getAddress(), addr.getMask());

            for (final InetAddress addr : config.getInterface().getDnsServers())
                builder.addDnsServer(addr.getHostAddress());

            for (final String dnsSearchDomain : config.getInterface().getDnsSearchDomains())
                builder.addSearchDomain(dnsSearchDomain);

            boolean sawDefaultRoute = false;
            for (final Peer peer : config.getPeers()) {
                for (final InetNetwork addr : peer.getAllowedIps()) {
                    if (addr.getMask() == 0)
                        sawDefaultRoute = true;
                    builder.addRoute(addr.getAddress(), addr.getMask());
                }
            }

            if (!(sawDefaultRoute && config.getPeers().size() == 1)) {
                builder.allowFamily(OsConstants.AF_INET);
                builder.allowFamily(OsConstants.AF_INET6);
            }

            // MTU БЕРЁТСЯ У ДВИЖКА, а не из настройки: путь данных читает пакеты окном ровно
            // такого размера и признака усечения не имеет, поэтому пакет крупнее пропал бы
            // целиком. Число приходит уже зажатым потолком.
            builder.setMtu((int) go.mtu());

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q)
                builder.setMetered(false);
            service.setUnderlyingNetworks(null);

            // Неблокирующий режим: контракт чтения у половины на Go — «когда пусто, сразу назад».
            builder.setBlocking(false);
            final ParcelFileDescriptor tun = builder.establish();
            if (tun == null)
                throw new BackendException(Reason.TUN_CREATION_ERROR);
            try {
                // detachFd, а не getFd: дескриптор переходит в собственность части на Go, и
                // закроет его она. С getFd его закрыли бы дважды, второй раз уже чужой,
                // переиспользованный номер, и проявилось бы это не здесь и не сразу.
                go.startFD(tun.detachFd(), tunnel.getName());
            } catch (final Exception e) {
                final Exception be = new BackendException(Reason.GO_ACTIVATION_ERROR_CODE, -1);
                be.initCause(e);
                throw be;
            }

            goTunnel = go;
            currentTunnel = tunnel;
            currentConfig = config;
            watchPath(context);
        } else {
            final xsteer.Tunnel go = goTunnel;
            if (go == null) {
                Log.w(TAG, "туннель уже снят");
                return;
            }
            goTunnel = null;
            currentTunnel = null;
            currentConfig = null;
            stopWatchingPath(context);
            // Stop ждёт, пока клиент отдаст накопленное и закроет дескриптор.
            go.stop();
            try {
                vpnService.get(0, TimeUnit.NANOSECONDS).stopSelf();
            } catch (final TimeoutException ignored) { }
        }

        tunnel.onStateChange(state);
    }

    /**
     * Сеть под туннелем сменилась: соединения надо переподнять, не дожидаясь таймаутов.
     */
    public void netChanged() {
        final xsteer.Tunnel go = goTunnel;
        if (go != null)
            go.netChanged();
    }

    /**
     * Слежение за тем, под чем живёт туннель. Своё слежение половины на Go выключено
     * (`NoNetWatch`): без netlink оно опрашивает адрес выхода раз в пять секунд, а внутри
     * туннеля адресом источника ядро может назвать адрес самого туннеля. Правду знает платформа
     * — значит платформа и обязана сказать.
     *
     * ДВА ИСТОЧНИКА, И ВТОРОЙ ВАЖНЕЕ ПЕРВОГО НА ТЕЛЕФОНЕ.
     *
     * 1. Смена сети: Wi-Fi ушёл, пришла мобильная. `registerDefaultNetworkCallback` — сеть ПО
     *    УМОЛЧАНИЮ, то есть та, в которой движок и открывает соединения к хабу (само приложение из
     *    туннеля исключено). Прежде стоял `registerNetworkCallback` с пустым запросом: он сообщает
     *    о КАЖДОЙ сети, какая есть у телефона, и сразу после регистрации — о каждой уже
     *    существующей. Пока смена поколения до режима потока не доходила, это было безвредно; теперь
     *    каждое такое извещение рвёт здоровые соединения. Поэтому реагируем только на СМЕНУ сети
     *    по умолчанию: первое извещение после регистрации — это та сеть, в которой туннель только
     *    что поднялся, и оно запоминается, а не исполняется.
     * 2. ВОЗВРАЩЕНИЕ ИЗ СНА. Экран гаснет, телефон засыпает, и всё, что у нас есть, —
     *    соединение TCP: оно переживает сон только до тех пор, пока его держит чужой NAT, а
     *    записей от нас в это время не уходит вовсе. Хаб освобождает сессию по простою,
     *    оператор закрывает трансляцию, и после разблокировки туннель «поднят», а не несёт
     *    ничего. Событий сети при этом НЕ БЫЛО — сеть та же самая, — поэтому первый источник
     *    молчит. Отсюда второй: включение экрана, разблокировка и выход из дремоты.
     *
     *    Включение экрана и разблокировка приходят парой, с разницей в секунды, и каждое
     *    извещение переподнимает все соединения. Поэтому они склеиваются: не чаще одного раза в
     *    WAKE_GAP_MS. Смена режима дремоты приходит и на входе в неё — там переподнимать нечего и
     *    не во что, — поэтому исполняется только выход.
     */
    private void watchPath(final Context context) {
        stopWatchingPath(context);

        final ConnectivityManager cm = context.getSystemService(ConnectivityManager.class);
        if (cm != null) {
            final ConnectivityManager.NetworkCallback cb = new ConnectivityManager.NetworkCallback() {
                // Обратные вызовы одного NetworkCallback приходят в одном потоке по очереди, так
                // что оба поля принадлежат ему и замка не требуют.
                private boolean seeded;
                @Nullable private Network current;

                @Override
                public void onAvailable(final Network network) {
                    if (!seeded) {
                        // Первое извещение после регистрации: сеть, в которой туннель только что
                        // поднялся. Сменой это не является.
                        seeded = true;
                        current = network;
                        return;
                    }
                    if (network.equals(current))
                        return;
                    current = network;
                    Log.i(TAG, "сеть сменилась — переподнимаю соединения");
                    netChanged();
                }

                @Override
                public void onLost(final Network network) {
                    // Сеть по умолчанию пропала, а замены нет: соединения в ней мертвы. Следующая
                    // появившаяся сеть отличается от «никакой» и переподнимет их ещё раз — уже
                    // туда, где путь есть.
                    if (!network.equals(current))
                        return;
                    current = null;
                    Log.i(TAG, "сеть пропала — переподнимаю соединения");
                    netChanged();
                }
            };
            try {
                cm.registerDefaultNetworkCallback(cb);
                netCallback = cb;
            } catch (final Exception e) {
                Log.w(TAG, "слежение за сетью не завелось: " + e.getMessage());
            }
        }

        final BroadcastReceiver rx = new BroadcastReceiver() {
            // Приёмник, зарегистрированный без Handler, зовётся в главном потоке — поле его.
            private long lastWakeAt = -WAKE_GAP_MS;

            @Override
            public void onReceive(final Context ctx, final Intent intent) {
                final String action = intent.getAction();
                if (PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED.equals(action)) {
                    final PowerManager pm = ctx.getSystemService(PowerManager.class);
                    if (pm == null || pm.isDeviceIdleMode())
                        return;
                }
                final long now = SystemClock.elapsedRealtime();
                if (now - lastWakeAt < WAKE_GAP_MS)
                    return;
                lastWakeAt = now;
                Log.i(TAG, "телефон проснулся (" + action + ") — переподнимаю соединения");
                netChanged();
            }
        };
        final IntentFilter f = new IntentFilter();
        f.addAction(Intent.ACTION_SCREEN_ON);
        f.addAction(Intent.ACTION_USER_PRESENT);
        // Все три — защищённые системные извещения, поэтому приёмнику не нужен признак
        // «кому видно»: с четырнадцатого Android он обязателен только тем, кто слушает и чужое.
        f.addAction(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED);
        try {
            context.registerReceiver(rx, f);
            wakeReceiver = rx;
        } catch (final Exception e) {
            Log.w(TAG, "слежение за пробуждением не завелось: " + e.getMessage());
        }
    }

    private void stopWatchingPath(final Context context) {
        if (netCallback != null) {
            try {
                final ConnectivityManager cm = context.getSystemService(ConnectivityManager.class);
                if (cm != null)
                    cm.unregisterNetworkCallback(netCallback);
            } catch (final Exception e) {
                Log.w(TAG, "снятие слежения за сетью: " + e.getMessage());
            }
            netCallback = null;
        }
        if (wakeReceiver != null) {
            try {
                context.unregisterReceiver(wakeReceiver);
            } catch (final Exception e) {
                Log.w(TAG, "снятие слежения за пробуждением: " + e.getMessage());
            }
            wakeReceiver = null;
        }
    }

    public interface AlwaysOnCallback {
        void alwaysOnTriggered();
    }

    /**
     * Служба системы, внутри которой живёт туннель.
     */
    public static class VpnService extends android.net.VpnService {
        @Nullable private GoBackend owner;

        public Builder getBuilder() {
            return new Builder();
        }

        @Override
        public void onCreate() {
            vpnService.complete(this);
            super.onCreate();
        }

        @Override
        public void onDestroy() {
            if (owner != null) {
                final Tunnel tunnel = owner.currentTunnel;
                if (tunnel != null) {
                    final xsteer.Tunnel go = owner.goTunnel;
                    owner.stopWatchingPath(owner.context);
                    if (go != null)
                        go.stop();
                    owner.goTunnel = null;
                    owner.currentTunnel = null;
                    owner.currentConfig = null;
                    tunnel.onStateChange(State.DOWN);
                }
            }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
                vpnService = vpnService.newIncompleteFuture();
            else
                vpnService = new CompletableFuture<>();
            super.onDestroy();
        }

        @Override
        public int onStartCommand(@Nullable final Intent intent, final int flags, final int startId) {
            vpnService.complete(this);
            if (intent == null || intent.getComponent() == null || !intent.getComponent().getPackageName().equals(getPackageName())) {
                Log.d(TAG, "службу подняла система: режим «всегда включён»");
                if (alwaysOnCallback != null)
                    alwaysOnCallback.alwaysOnTriggered();
            }
            return super.onStartCommand(intent, flags, startId);
        }

        public void setOwner(final GoBackend owner) {
            this.owner = owner;
        }
    }
}
