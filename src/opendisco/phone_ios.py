"""The iOS side of OpenDisco's phone screens (phone.py): UIKit through rubicon-objc.

Toga's iOS backend lays out the content but has no navigation, title-bar buttons, button styles,
share sheet or clipboard; these give phone.py those, under the names phone.py's docstring lists.
"""
from pathlib import Path

from opendisco import phone

# SF Symbols for the device page's tabs, in place of Toga's star on every one
TAB_SYMBOLS = {"Details": "info.circle", "Packets": "doc.text.magnifyingglass", "Tools": "wrench.and.screwdriver",
               "Notes": "text.bubble", "Log": "list.bullet.rectangle"}


def _objc(name):
    from rubicon.objc import ObjCClass
    return ObjCClass(name)


def _class_value(cls, name):
    """A class property (UIColor.systemRedColor...), however rubicon hands it over."""
    from rubicon.objc import ObjCInstance
    value = getattr(cls, name)
    return value if isinstance(value, ObjCInstance) else value()


class BarItem:
    """A title-bar button that app.py enables and disables like a Toga one (Export)."""

    def __init__(self, native):
        self.native = native

    @property
    def enabled(self) -> bool:
        return bool(self.native.isEnabled())

    @enabled.setter
    def enabled(self, value):
        self.native.enabled = bool(value)


class Page:
    """A page pushed over the device list, holding Toga content, with the title bar's back
    button (and the swipe from the left edge) to return."""

    def __init__(self, app, content):
        from toga_iOS.container import ControlledContainer
        self.app, self.content, self.laid_out = app, content, None
        self.container = ControlledContainer(on_refresh=lambda container: None, on_native_layout=self._layout)
        content.app = app
        self.container.content = content._impl
        self.controller = self.container.controller
        self.controller.view.backgroundColor = _class_value(_objc("UIColor"), "systemBackgroundColor")

    def _layout(self, container):
        """Lay the content out below the title bar whenever the page changes size (rotation)."""
        bar = self.app.main_window._impl.container.controller.navigationBar
        top = bar.frame.origin.y + bar.frame.size.height
        size = (container.native.bounds.size.width, container.native.bounds.size.height, top)
        if size != self.laid_out:
            self.laid_out = size
            container.top_inset = top
            self.content.refresh()

    def show(self, title: str, subtitle: str):
        from rubicon.objc import SEL
        item = self.controller.navigationItem
        if item.respondsToSelector(SEL("setSubtitle:")):  # iOS 26 and later
            item.title, item.subtitle = title, subtitle
        else:
            item.title = f"{title}  {subtitle}" if subtitle and subtitle != title else title
        nav = self.app.main_window._impl.container.controller
        if nav.topViewController != self.controller:
            nav.pushViewController(self.controller, animated=True)

    def close(self):
        nav = self.app.main_window._impl.container.controller
        if nav.topViewController == self.controller:
            nav.popViewControllerAnimated(True)


def fit(app, export, notes, settings):
    """The title bar's buttons (Export at the left; Notes and Log, Settings at the right), lines
    between devices, an icon for each tab."""
    from rubicon.objc import Block, objc_id
    app._ios_blocks = []  # the buttons' handlers, kept alive

    def item(symbol, title, action):
        def tapped(_action) -> None:
            try:
                action()
            except Exception as e:  # UIKit would drop it silently
                app.status.text = f"{title}: {type(e).__name__}: {e}"

        block = Block(tapped, None, objc_id)
        app._ios_blocks.append(block)
        act = _objc("UIAction").actionWithTitle(title, image=_objc("UIImage").systemImageNamed(symbol),
                                                identifier=None, handler=block)
        return _objc("UIBarButtonItem").alloc().initWithPrimaryAction(act)

    bar = app.main_window._impl.container.content_controller.navigationItem
    export_item = item("square.and.arrow.up", "Export", export)
    bar.leftBarButtonItem = export_item
    bar.rightBarButtonItems = _objc("NSArray").arrayWithArray([item("gearshape", "Settings", settings),
                                                               item("list.bullet.rectangle", "Notes and Log", notes)])
    bar.backButtonTitle = "Devices"
    app.export_button = BarItem(export_item)
    app.export_button.enabled = False
    try:
        app.table._impl.native.separatorStyle = 1  # UITableViewCellSeparatorStyleSingleLine
        UIImage = _objc("UIImage")
        for tab in app.tabs._impl.sub_containers:
            image = UIImage.systemImageNamed(TAB_SYMBOLS.get(str(tab.controller.tabBarItem.title), ""))
            if image:
                tab.controller.tabBarItem.image = image
    except Exception:
        pass  # cosmetic


def style_button(button, kind="filled", color=None):
    """A rounded, filled or tinted iOS button (UIButton.Configuration) in place of plain text."""
    try:
        Config = _objc("UIButtonConfiguration")
        config = {"filled": Config.filledButtonConfiguration, "tinted": Config.tintedButtonConfiguration,
                  "gray": Config.grayButtonConfiguration}[kind]()
        config.cornerStyle = 4  # capsule
        config.title = button.text
        if color:
            tint = _class_value(_objc("UIColor"), color)
            config.baseForegroundColor = tint
            config.baseBackgroundColor = tint
        native = button._impl.native
        native.setTitle(None, forState=0)  # Toga's title would keep its own colour: blue on the blue fill
        native.configuration = config
        button.refresh()
    except Exception:
        pass  # cosmetic: a plain button still works


def retitle(button, text: str):
    """Change a button's text, styled or not."""
    native = button._impl.native
    config = native.configuration
    if config is None:
        button.text = text
    elif str(config.title) != text:
        config.title = text
        native.configuration = config
        button.refresh()


def monospaced(text, size: float):
    """The system's monospaced font (SF Mono), which reads better than the Courier Toga picks."""
    try:
        text._impl.native.font = _objc("UIFont").monospacedSystemFontOfSize(size, weight=0.0)
    except Exception:
        pass  # cosmetic


def copy_text(text: str):
    _class_value(_objc("UIPasteboard"), "generalPasteboard").string = text


def keep_selection(app, key):
    """The list forgets which row was tapped whenever a row changes, and with it which device
    Tools works on: select the same device again."""
    if key is None:
        return
    index = next((i for i, row in enumerate(app.table.data) if getattr(row, "key", None) == key), None)
    if index is None:
        return
    try:
        path = _objc("NSIndexPath").indexPathForRow(index, inSection=0)
        app.table._impl.native.selectRowAtIndexPath(path, animated=False, scrollPosition=0)  # no scrolling
    except Exception:
        pass


def fit_safe_area(app):
    """Keep the device list inside the screen's rounded corners and clear of the home bar (and,
    turned sideways, the camera cutout): Toga lays it out to the very edges."""
    try:
        inset = app.main_window._impl.native.safeAreaInsets
        style = app.main_content.style
        style.margin_bottom = max(10, int(inset.bottom))
        style.margin_left, style.margin_right = max(10, int(inset.left)), max(10, int(inset.right))
    except Exception:
        pass  # cosmetic


def export(app, name: str):
    """Save the report in the app's own folder and offer it to the share sheet."""
    share(app, phone.export_file(app, name))


def share(app, path: Path):
    """Offer a file to the share sheet: Save to Files, Mail, AirDrop, Messages…"""
    from rubicon.objc import Block, objc_id
    url = _objc("NSURL").fileURLWithPath(str(path))
    sheet = _objc("UIActivityViewController").alloc().initWithActivityItems(
        _objc("NSArray").arrayWithObject(url), applicationActivities=None)
    popover = sheet.popoverPresentationController  # iPad: the sheet points at the Export button
    if popover:
        popover.barButtonItem = app.export_button.native

    def done(activity, completed: bool, items, error) -> None:
        app.status.text = f"Shared {path.name}" if completed else "Export not shared."

    app._share_done = Block(done, None, objc_id, bool, objc_id, objc_id)  # kept alive while it's up
    sheet.completionWithItemsHandler = app._share_done
    shown = app.main_window._impl.native.rootViewController
    while shown.presentedViewController:
        shown = shown.presentedViewController
    shown.presentViewController(sheet, animated=True, completion=None)
    app.status.text = f"Saved {path.name}: share it to Files, Mail or AirDrop."
