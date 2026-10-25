"""The Android side of OpenDisco's phone screens (phone.py): Android's views through Chaquopy.

phone_ios.py draws the phone layout with UIKit; this draws the same with Android's own pieces,
under the names phone.py's docstring lists: the ActionBar is the title bar (Export, Notes and
Log, Settings; on a page, the Up arrow with the page's title and subtitle), the system Back
button and gesture go back like Up (app._android_back), and the tabs are Material's bottom
navigation bar. Colours and button shapes follow the iPhone's.

Everything here runs on the UI thread, and all of it is cosmetic except Page, Up and Back: when
a native call fails the plain Toga widget is left as it was.
"""
import traceback

import toga

# The iPhone's system colours (light mode), as Android colour ints (ARGB)
BLUE, RED, GREEN = 0xFF007AFF, 0xFFFF3B30, 0xFF34C759
LABEL, SECONDARY = 0xFF1C1C1E, 0xFF8A8A8E
BAR = 0xFFF9F9F9  # the title bar, status bar and tab bar
FILL = 0xFFE9E9EB  # a gray button
DISABLED_FILL, DISABLED_TEXT = 0xFFF0F0F2, 0xFFB4B4B9
SEPARATOR = 0xFFD8D8DC
COLORS = {"systemBlueColor": BLUE, "systemRedColor": RED, "systemGreenColor": GREEN}
BAR_ICONS = {"Export": "ios_share", "Notes and Log": "list_alt", "Settings": "settings"}
TAB_ICONS = {"Details": "info", "Packets": "manage_search", "Tools": "build", "Notes": "chat_bubble", "Log": "list_alt"}
# Material Symbols (Outlined, 24 px; Google, Apache License 2.0): SVG path data, drawn by _icon.
# Like the iPhone's SF Symbols, in place of Android's dated built-in menu icons.
SYMBOLS = {
    "ios_share": (
        "M240-40q-33 0-56.5-23.5T160-120v-440q0-33 23.5-56.5T240-640h120v80H240v440h480v-440H600v-80h120q"
        "33 0 56.5 23.5T800-560v440q0 33-23.5 56.5T720-40H240Zm200-280v-447l-64 64-56-57 160-160 160 160-"
        "56 57-64-64v447h-80Z"),
    "list_alt": (
        "M320-280q17 0 28.5-11.5T360-320q0-17-11.5-28.5T320-360q-17 0-28.5 11.5T280-320q0 17 11.5 28.5T32"
        "0-280Zm0-160q17 0 28.5-11.5T360-480q0-17-11.5-28.5T320-520q-17 0-28.5 11.5T280-480q0 17 11.5 28."
        "5T320-440Zm0-160q17 0 28.5-11.5T360-640q0-17-11.5-28.5T320-680q-17 0-28.5 11.5T280-640q0 17 11.5"
        " 28.5T320-600Zm120 320h240v-80H440v80Zm0-160h240v-80H440v80Zm0-160h240v-80H440v80ZM200-120q-33 0"
        "-56.5-23.5T120-200v-560q0-33 23.5-56.5T200-840h560q33 0 56.5 23.5T840-760v560q0 33-23.5 56.5T760"
        "-120H200Zm0-80h560v-560H200v560Zm0-560v560-560Z"),
    "settings": (
        "m370-80-16-128q-13-5-24.5-12T307-235l-119 50L78-375l103-78q-1-7-1-13.5v-27q0-6.5 1-13.5L78-585l1"
        "10-190 119 50q11-8 23-15t24-12l16-128h220l16 128q13 5 24.5 12t22.5 15l119-50 110 190-103 78q1 7 "
        "1 13.5v27q0 6.5-2 13.5l103 78-110 190-118-50q-11 8-23 15t-24 12L590-80H370Zm70-80h79l14-106q31-8"
        " 57.5-23.5T639-327l99 41 39-68-86-65q5-14 7-29.5t2-31.5q0-16-2-31.5t-7-29.5l86-65-39-68-99 42q-2"
        "2-23-48.5-38.5T533-694l-13-106h-79l-14 106q-31 8-57.5 23.5T321-633l-99-41-39 68 86 64q-5 15-7 30"
        "t-2 32q0 16 2 31t7 30l-86 65 39 68 99-42q22 23 48.5 38.5T427-266l13 106Zm42-180q58 0 99-41t41-99"
        "q0-58-41-99t-99-41q-59 0-99.5 41T342-480q0 58 40.5 99t99.5 41Zm-2-140Z"),
    "info": (
        "M440-280h80v-240h-80v240Zm40-320q17 0 28.5-11.5T520-640q0-17-11.5-28.5T480-680q-17 0-28.5 11.5T4"
        "40-640q0 17 11.5 28.5T480-600Zm0 520q-83 0-156-31.5T197-197q-54-54-85.5-127T80-480q0-83 31.5-156"
        "T197-763q54-54 127-85.5T480-880q83 0 156 31.5T763-763q54 54 85.5 127T880-480q0 83-31.5 156T763-1"
        "97q-54 54-127 85.5T480-80Zm0-80q134 0 227-93t93-227q0-134-93-227t-227-93q-134 0-227 93t-93 227q0"
        " 134 93 227t227 93Zm0-320Z"),
    "manage_search": (
        "M80-200v-80h400v80H80Zm0-200v-80h200v80H80Zm0-200v-80h200v80H80Zm744 400L670-354q-24 17-52.5 25."
        "5T560-320q-83 0-141.5-58.5T360-520q0-83 58.5-141.5T560-720q83 0 141.5 58.5T760-520q0 29-8.5 57.5"
        "T726-410l154 154-56 56ZM560-400q50 0 85-35t35-85q0-50-35-85t-85-35q-50 0-85 35t-35 85q0 50 35 85"
        "t85 35Z"),
    "build": (
        "M686-132 444-376q-20 8-40.5 12t-43.5 4q-100 0-170-70t-70-170q0-36 10-68.5t28-61.5l146 146 72-72-"
        "146-146q29-18 61.5-28t68.5-10q100 0 170 70t70 170q0 23-4 43.5T584-516l244 242q12 12 12 29t-12 29"
        "l-84 84q-12 12-29 12t-29-12Zm29-85 27-27-256-256q18-20 26-46.5t8-53.5q0-60-38.5-104.5T386-758l74"
        " 74q12 12 12 28t-12 28L332-500q-12 12-28 12t-28-12l-74-74q9 57 53.5 95.5T360-440q26 0 52-8t47-25"
        "l256 256ZM472-488Z"),
    "chat_bubble": (
        "M80-80v-720q0-33 23.5-56.5T160-880h640q33 0 56.5 23.5T880-800v480q0 33-23.5 56.5T800-240H240L80-"
        "80Zm126-240h594v-480H160v525l46-45Zm-46 0v-480 480Z"),
}


def _int(color: int) -> int:
    """An ARGB colour as Java's signed int."""
    return color - (1 << 32) if color >= 1 << 31 else color


def _activity():
    from org.beeware.android import MainActivity
    return MainActivity.singletonThis


def _dp(value: float) -> int:
    return int(value * _activity().getResources().getDisplayMetrics().density + 0.5)


def _states(state: str, on: int, off: int):
    """A ColorStateList: one colour in the state ("enabled", "checked"), another otherwise."""
    from java import jarray, jclass, jint
    attr = getattr(jclass("android.R$attr"), f"state_{state}")
    return jclass("android.content.res.ColorStateList")(jarray(jarray(jint))([[attr], []]),
                                                         jarray(jint)([_int(on), _int(off)]))


def _icon(name: str, color: int = LABEL, size: float = 24):
    """A Material Symbol, size dp square, tinted."""
    from java import jclass
    Bitmap, Matrix, Paint = (jclass(f"android.graphics.{n}") for n in ("Bitmap", "Matrix", "Paint"))
    pixels = _dp(size)
    path = jclass("androidx.core.graphics.PathParser").createPathFromPathData(SYMBOLS[name])
    fit = Matrix()
    fit.setTranslate(0.0, 960.0)  # the symbols' view box is 0 -960 960 960
    fit.postScale(pixels / 960, pixels / 960)
    path.transform(fit)
    bitmap = Bitmap.createBitmap(pixels, pixels, Bitmap.Config.ARGB_8888)
    paint = Paint(Paint.ANTI_ALIAS_FLAG)
    paint.setARGB(255, 255, 255, 255)  # (setColor would take Python's int for a colour long)
    jclass("android.graphics.Canvas")(bitmap).drawPath(path, paint)
    drawable = jclass("android.graphics.drawable.BitmapDrawable")(_activity().getResources(), bitmap)
    drawable.setTint(_int(color))
    return drawable


# -- buttons -----------------------------------------------------------------------
def style_button(button, kind="filled", color=None):
    """A capsule button like the iPhone's: filled (white on the colour), tinted (the colour on a
    pale wash of it) or gray (blue on gray); pale gray while disabled."""
    try:
        from java import jclass
        tint = COLORS.get(color, BLUE)
        fill, text = {"filled": (tint, 0xFFFFFFFF), "tinted": ((tint & 0xFFFFFF) | 0x24000000, tint),
                      "gray": (FILL, BLUE)}[kind]
        shape = jclass("android.graphics.drawable.GradientDrawable")()
        shape.setCornerRadius(_dp(100))  # clamped to half the height: a capsule
        shape.setColor(_states("enabled", fill, DISABLED_FILL))
        ripple = jclass("android.content.res.ColorStateList").valueOf(_int(0x33000000))
        native = button._impl.native
        native.setBackground(jclass("android.graphics.drawable.RippleDrawable")(ripple, shape, None))
        native.setTextColor(_states("enabled", text, DISABLED_TEXT))
        native.setAllCaps(False)
        native.setStateListAnimator(None)  # no shadow under it
        native.setTextSize(jclass("android.util.TypedValue").COMPLEX_UNIT_SP, 16)
        native.setMinHeight(_dp(44))
        native.setMinimumHeight(_dp(44))
        native.setPadding(_dp(12), 0, _dp(12), 0)
        button.refresh()
    except Exception:
        traceback.print_exc()  # cosmetic: a plain button still works


def retitle(button, text: str):
    """Change a button's text (the styling stays)."""
    if button.text != text:
        button.text = text


# -- pages -------------------------------------------------------------------------
class Page:
    """A page over the device list: its content in place of the list's, and the title bar
    showing its title and subtitle with the Up arrow. Up, Back and the back gesture return."""

    def __init__(self, app, content, on_back=None):
        self.app, self.content, self.on_back = app, content, on_back

    def show(self, title: str, subtitle: str = ""):
        self.app._push_page(self.content, title, subtitle, on_back=self.on_back)

    def close(self):
        self.app._pop_page(self.content)


def show_bar(app):
    """The title bar for what's on top: a page's title and subtitle with the Up arrow, or the
    app's name with its buttons."""
    try:
        bar = _activity().getSupportActionBar()
        if app._panels:
            _content, _back, title, subtitle = app._panels[-1]
            bar.setTitle(title)
            bar.setSubtitle(subtitle or None)
            bar.setDisplayHomeAsUpEnabled(True)
        else:
            bar.setTitle(app.main_window.title)
            bar.setSubtitle(None)
            bar.setDisplayHomeAsUpEnabled(False)
        _activity().invalidateOptionsMenu()  # the buttons belong to the device list
    except Exception:
        traceback.print_exc()


class CommandButton:
    """A title-bar button that app.py enables and disables like a Toga button (Export)."""

    def __init__(self, command):
        self.command = command

    @property
    def enabled(self) -> bool:
        return self.command.enabled

    @enabled.setter
    def enabled(self, value):
        self.command.enabled = bool(value)


def fit(app, export, notes, settings):
    """The title bar's buttons (Export, Notes and Log, Settings), Up, the system bars, the tabs'
    icons and the device list's look."""
    def command(text, action, order):
        return toga.Command(lambda command, **kwargs: action(), text=text, group=toga.Group.COMMANDS, order=order)

    export_command = command("Export", export, 1)
    export_command.enabled = False
    app.main_window.toolbar.add(export_command, command("Notes and Log", notes, 2), command("Settings", settings, 3))
    app.export_button = CommandButton(export_command)
    for fitting in (_take_up_and_menu, _fit_system_bars, _fit_tabs, _fit_list):
        try:
            fitting(app)
        except Exception:
            traceback.print_exc()
    show_bar(app)


def _take_up_and_menu(app):
    """Up goes back, like Back; the title bar's buttons get icons, and are hidden on a page (Toga
    would hand Up to a command that isn't there, and has no icons for these)."""
    from java import jclass
    listener = app._impl._listener
    home = jclass("android.R$id").home
    toga_selected, toga_prepare = listener.onOptionsItemSelected, listener.onPrepareOptionsMenu

    def selected(item):
        if item.getItemId() == home:
            app._back()
            return True
        return toga_selected(item)

    def prepare(menu):
        shown = toga_prepare(menu)
        try:
            for index in range(menu.size()):
                item = menu.getItem(index)
                item.setVisible(not app._panels)
                name = BAR_ICONS.get(str(item.getTitle()))
                if name:
                    item.setIcon(_icon(name, LABEL if item.isEnabled() else DISABLED_TEXT))
            overflow = _toolbar().getOverflowIcon()
            if overflow is not None:
                overflow.setTint(_int(LABEL))
        except Exception:
            traceback.print_exc()
        return shown

    listener.onOptionsItemSelected = selected
    listener.onPrepareOptionsMenu = prepare


def _toolbar():
    """The ActionBar's own Toolbar view."""
    from java import jclass
    return _activity().findViewById(jclass("androidx.appcompat.R$id").action_bar)


def _fit_system_bars(app):
    """A light title bar and status bar, like the iPhone's, in place of the theme's dark ones."""
    from java import jclass
    activity = _activity()
    bar = activity.getSupportActionBar()
    bar.setBackgroundDrawable(jclass("android.graphics.drawable.ColorDrawable")(_int(BAR)))
    bar.setElevation(0)
    toolbar = _toolbar()
    toolbar.setTitleTextColor(_int(LABEL))
    toolbar.setSubtitleTextColor(_int(SECONDARY))
    up = activity.getDrawable(jclass("androidx.appcompat.R$drawable").abc_ic_ab_back_material).mutate()
    up.setTint(_int(BLUE))
    bar.setHomeAsUpIndicator(up)
    window = activity.getWindow()
    window.setStatusBarColor(_int(BAR))
    content = activity.findViewById(jclass("android.R$id").content)
    parent = content.getParent()  # Briefcase draws the status bar's colour with a plain View there
    for index in range(parent.getChildCount()):
        child = parent.getChildAt(index)
        if child.getClass().getName() == "android.view.View":
            child.setBackgroundColor(_int(BAR))
    jclass("androidx.core.view.WindowCompat").getInsetsController(window, window.getDecorView()) \
        .setAppearanceLightStatusBars(True)


def _fit_tabs(app):
    """Icons for the tabs in place of Toga's star, and a tab that's turned off is hidden, as on
    the iPhone (the scan's Notes and Log page has no Details, Packets or Tools)."""
    impl = app.tabs._impl
    toga_enabled = impl.set_option_enabled

    def set_enabled(index, enabled):
        toga_enabled(index, enabled)
        item = impl.options[index].menu_item
        if item is not None:
            item.setVisible(bool(enabled))

    impl.set_option_enabled = set_enabled
    for option in impl.options:
        if option.menu_item is not None:
            name = TAB_ICONS.get(option.text)
            if name:
                option.menu_item.setIcon(_icon(name))
            option.menu_item.setVisible(option.enabled)
    view = impl.native_navigationview
    tints = _states("checked", BLUE, SECONDARY)  # the tab that's showing, the others
    view.setItemIconTintList(tints)
    view.setItemTextColor(tints)
    view.setBackgroundColor(_int(BAR))


def _fit_list(app):
    """The device list as the iPhone shows it: the address over the model and name, a line
    between devices, no space for an icon, a ripple where it's tapped rather than a row that
    stays grey; a changed row is redrawn in place (Toga would redraw the whole list, losing the
    selection, every second of a scan)."""
    from java import jclass
    View, RelativeLayout = jclass("android.view.View"), jclass("android.widget.RelativeLayout")
    TypedValue, ripple = jclass("android.util.TypedValue"), jclass("android.R$attr").selectableItemBackground
    impl = app.table._impl
    toga_make_row = impl._make_row
    margin = _dp(16)

    def make_row(container, i, row):
        toga_make_row(container, i, row)
        try:
            view = container.getChildAt(container.getChildCount() - 1)
            value = TypedValue()
            view.getContext().getTheme().resolveAttribute(ripple, value, True)
            view.setBackground(view.getContext().getDrawable(value.resourceId))
            icon, texts = view.getChildAt(0), view.getChildAt(1)
            icon.setVisibility(View.GONE)
            params = texts.getLayoutParams()
            params.setMargins(margin, 0, margin, 0)
            texts.setLayoutParams(params)
            texts.getChildAt(0).setTextSize(17.0)
            texts.getChildAt(0).setTextColor(_int(LABEL))
            texts.getChildAt(1).setTextSize(15.0)
            texts.getChildAt(1).setTextColor(_int(SECONDARY))
            line = View(view.getContext())
            line.setBackgroundColor(_int(SEPARATOR))
            line_params = RelativeLayout.LayoutParams(RelativeLayout.LayoutParams.MATCH_PARENT, max(1, _dp(0.5)))
            line_params.addRule(RelativeLayout.ALIGN_PARENT_BOTTOM)
            line_params.setMargins(margin, 0, 0, 0)
            view.addView(line, line_params)
        except Exception:
            traceback.print_exc()

    def source_change(*, item):
        try:
            index = list(impl.interface.data).index(item)
            texts = impl._get_row(index).getChildAt(1)
            missing = impl.interface.missing_value
            title, subtitle = (getattr(item, attr, None) for attr in impl.interface.accessors[:2])
            texts.getChildAt(0).setText(str(missing if title is None else title))
            texts.getChildAt(1).setText(str(missing if subtitle is None else subtitle))
        except Exception:
            impl._load_data()

    impl._make_row = make_row
    impl.source_change = source_change
    impl._set_selection = lambda index: setattr(impl, "_selection", index)  # no grey row
    impl._clear_selection = lambda: setattr(impl, "_selection", None)
    impl._load_data()


def keep_selection(app, key):
    """Select the device's row again after the list was rebuilt (a device was found), without
    telling on_select: Tools works on the selected device."""
    if key is None:
        return
    index = next((i for i, row in enumerate(app.table.data) if getattr(row, "key", None) == key), None)
    if index is not None:
        app.table._impl._selection = index


def fit_safe_area(app):
    """Nothing to do: Briefcase's activity keeps the content inside the system bars."""


def monospaced(text, size: float):
    """Android's monospaced font, and no underline under the text (it's read, not typed)."""
    text.style.update(font_family="monospace", font_size=size)
    try:
        from java import jclass
        native = text._impl.native
        if not isinstance(native.getBackground(), jclass("android.graphics.drawable.ColorDrawable")):
            native.setBackground(None)  # (the console keeps its colour)
            native.setPadding(_dp(4), _dp(4), _dp(4), _dp(4))
    except Exception:
        traceback.print_exc()


# -- the clipboard and exports -------------------------------------------------------
def copy_text(text: str):
    from java import jclass
    board = _activity().getSystemService(jclass("android.content.Context").CLIPBOARD_SERVICE)
    board.setPrimaryClip(jclass("android.content.ClipData").newPlainText("OpenDisco", text))


def export(app, name: str):
    """Save the report in Downloads, where a file manager or browser opens it."""
    from opendisco import core
    app.status.text = f"Saved {app._save_to_downloads(name, core.export_text(app.result, '.html'))}"
