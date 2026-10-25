"""The iOS side of OpenDisco's phone screens (phone.py): UIKit through rubicon-objc.

Toga's iOS backend lays out the content but has no navigation, title-bar buttons, button styles,
share sheet or clipboard; these give phone.py those, under the names phone.py's docstring lists.
"""
from pathlib import Path

import toga
from toga.style import Pack

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


_NAV_WATCHER = None
_open_pages = []  # Pages pushed and not closed yet, to tell when Back took one off


def _nav_watcher():
    """The navigation controller's delegate: after Back (the button or the swipe) a page that was
    on the stack is gone from it without its close() having run, and its on_back runs. (A page
    whose push waits for another page's closing animation isn't on the stack yet: not Back.)"""
    global _NAV_WATCHER
    if _NAV_WATCHER is None:
        from rubicon.objc import NSObject, objc_method

        class OpenDiscoNavigationWatcher(NSObject):
            @objc_method
            def navigationController_didShowViewController_animated_(self, nav, shown, animated: bool) -> None:
                stack = list(nav.viewControllers)
                for page in _open_pages:
                    page.stacked = page.stacked or page.controller in stack
                for page in [p for p in _open_pages if p.stacked and p.controller not in stack]:
                    _open_pages.remove(page)
                    if page.on_back:
                        page.on_back()

        _NAV_WATCHER = OpenDiscoNavigationWatcher.alloc().init()
    return _NAV_WATCHER


class Page:
    """A page pushed over the device list, holding Toga content, with the title bar's back
    button (and the swipe from the left edge) to return: then on_back runs."""

    def __init__(self, app, content, on_back=None):
        from toga_iOS.container import ControlledContainer
        self.app, self.content, self.laid_out, self.on_back = app, content, None, on_back
        self.stacked = False  # seen on the navigation stack
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
        nav.delegate = _nav_watcher()
        if self not in _open_pages:
            _open_pages.append(self)
        if nav.topViewController != self.controller:
            nav.pushViewController(self.controller, animated=True)

    def close(self):
        if self in _open_pages:
            _open_pages.remove(self)
        nav = self.app.main_window._impl.container.controller
        if self.controller in list(nav.viewControllers):  # this page, and any pushed over it
            index = list(nav.viewControllers).index(self.controller)
            nav.popToViewController(nav.viewControllers[index - 1], animated=True)


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


class Picker:
    """A pop-up button: it shows the item chosen, and tapping it lists the others (iOS 15's
    pop-up menu, in place of Toga's picker wheel)."""

    def __init__(self, app, items):
        from rubicon.objc import Block, objc_id
        self.items, self.value = list(items), items[0]
        self.widget = toga.Button(items[0], style=Pack(flex=1))
        self._blocks = []
        actions = []
        for item in self.items:
            def picked(_action, item=item) -> None:
                self.value = item

            self._blocks.append(Block(picked, None, objc_id))
            actions.append(_objc("UIAction").actionWithTitle(item, image=None, identifier=None,
                                                             handler=self._blocks[-1]))
        actions[0].state = 1  # UIMenuElementStateOn: the one chosen
        native = self.widget._impl.native
        native.menu = _objc("UIMenu").menuWithTitle("", children=_objc("NSArray").arrayWithArray(actions))
        native.showsMenuAsPrimaryAction = True
        native.changesSelectionAsPrimaryAction = True
        style_button(self.widget, "gray")


def watch_keyboard(app, widget):
    """Keep a text view's last lines above the on-screen keyboard while it's up (the SSH
    session's console, as commands are typed under it)."""
    try:
        from rubicon.objc import Block, ObjCInstance, objc_id
        from rubicon.objc.types import UIEdgeInsetsMake
        center = _class_value(_objc("NSNotificationCenter"), "defaultCenter")

        def moved(note) -> None:
            view = widget._impl.native
            if view.window is None:
                return
            keyboard = ObjCInstance(note).userInfo.objectForKey("UIKeyboardFrameEndUserInfoKey").CGRectValue
            mine = view.convertRect(view.bounds, toView=None)
            covered = max(0.0, mine.origin.y + mine.size.height - keyboard.origin.y)
            view.contentInset = UIEdgeInsetsMake(0, 0, covered, 0)
            view.verticalScrollIndicatorInsets = UIEdgeInsetsMake(0, 0, covered, 0)
            widget.scroll_to_bottom()

        app._keyboard_block = Block(moved, None, objc_id)  # kept alive, as the observer
        app._keyboard_observer = center.addObserverForName("UIKeyboardWillChangeFrameNotification", object=None,
                                                           queue=None, usingBlock=app._keyboard_block)
    except Exception:
        pass  # the console still scrolls by hand


def plain_entry(widget, send: bool = False):
    """A text field for usernames, passwords, ports and shell commands: no capital first letter,
    no corrections, no smart quotes; send: its return key reads "send". (Set through the setters:
    rubicon doesn't find UITextInputTraits' properties on a UITextField.)"""
    native = widget._impl.native
    for setter, value in (("setAutocapitalizationType:", 0), ("setAutocorrectionType:", 1),
                          ("setSpellCheckingType:", 1), ("setSmartQuotesType:", 1), ("setSmartDashesType:", 1),
                          ("setSmartInsertDeleteType:", 1), *((("setReturnKeyType:", 7),) if send else ())):
        try:
            from rubicon.objc import NSInteger, send_message
            send_message(native, setter, value, restype=None, argtypes=[NSInteger])
        except Exception:
            pass


def end_editing(app):
    """Finish typing: the text field gives up the keyboard, and its last character (still
    pending in a password field) is in its value."""
    try:
        app.main_window._impl.native.endEditing(True)
    except Exception:
        pass
