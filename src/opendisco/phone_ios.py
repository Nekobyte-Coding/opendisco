"""The iOS side of OpenDisco's phone screens (phone.py): UIKit through rubicon-objc.

Toga's iOS backend lays out the content but has no navigation, title-bar buttons, button styles,
share sheet or clipboard; these give phone.py those, under the names phone.py's docstring lists.

On an iPad at a regular width (full screen in either orientation, the larger side of Split View,
a wide Stage Manager window) the device list stays in a column at the left and the pages open
beside it, in a split view (_Split). At a compact width the iPad app is the iPhone's: pages are
pushed over the list. Changing between the two moves the open pages across.
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
_moving = False  # pages moving between the iPhone layout and the split view: not Back


def _nav_watcher():
    """The navigation controllers' delegate: after Back (the button or the swipe) a page that was
    on a stack is on none without its close() having run, and its on_back runs. (A page whose
    push waits for another page's closing animation isn't on the stack yet: not Back.)"""
    global _NAV_WATCHER
    if _NAV_WATCHER is None:
        from rubicon.objc import NSObject, objc_method

        class OpenDiscoNavigationWatcher(NSObject):
            @objc_method
            def navigationController_didShowViewController_animated_(self, nav, shown, animated: bool) -> None:
                if _moving:
                    return
                apps = {id(page.app): page.app for page in _open_pages}
                for page in list(_open_pages):
                    if page.controller.navigationController is not None:
                        page.stacked = True
                    elif page.stacked:
                        _open_pages.remove(page)
                        if page.on_back:
                            page.on_back()
                for app in apps.values():
                    _split(app).fit_list()

        _NAV_WATCHER = OpenDiscoNavigationWatcher.alloc().init()
    return _NAV_WATCHER


def _phone_nav(app):
    """The navigation controller of the window: the device list, and on an iPhone the pages too."""
    return app.main_window._impl.container.controller


class Page:
    """A page over the device list, holding Toga content, with the title bar's back button (and
    the swipe from the left edge) to return: then on_back runs. On an iPad beside the list, the
    device page (app.page) fills the right-hand column and the others are pushed over it."""

    def __init__(self, app, content, on_back=None):
        from toga_iOS.container import ControlledContainer
        self.app, self.content, self.laid_out, self.on_back = app, content, None, on_back
        self.stacked = False  # seen on a navigation stack
        self.container = ControlledContainer(on_refresh=lambda container: None, on_native_layout=self._layout)
        content.app = app
        self.container.content = content._impl
        self.controller = self.container.controller
        self.controller.view.backgroundColor = _class_value(_objc("UIColor"), "systemBackgroundColor")

    def _layout(self, container):
        """Lay the content out below the title bar whenever the page changes size (rotation), and
        beside the list's column, which the right-hand one runs under."""
        bar = (self.controller.navigationController or _phone_nav(self.app)).navigationBar
        top = bar.frame.origin.y + bar.frame.size.height
        left = right = 0
        if _split(self.app).view is not None:
            insets = container.native.safeAreaInsets
            left, right = insets.left, insets.right
        size = (container.native.bounds.size.width, container.native.bounds.size.height, top, left, right)
        if size != self.laid_out:
            self.laid_out = size
            container.top_inset, container.left_inset, container.right_inset = top, left, right
            self.content.refresh()

    def show(self, title: str, subtitle: str):
        from rubicon.objc import SEL
        item = self.controller.navigationItem
        if item.respondsToSelector(SEL("setSubtitle:")):  # iOS 26 and later
            item.title, item.subtitle = title, subtitle
        else:
            item.title = f"{title}  {subtitle}" if subtitle and subtitle != title else title
        if self not in _open_pages:
            _open_pages.append(self)
        split = _split(self.app)
        if split.view is not None and self is getattr(self.app, "page", None):
            if split.detail.viewControllers[0] != self.controller:  # in place of the one beside the list
                split.detail.setViewControllers([self.controller], animated=False)
        else:
            nav = split.detail if split.view is not None else _phone_nav(self.app)
            nav.delegate = _nav_watcher()
            if nav.topViewController != self.controller:
                nav.pushViewController(self.controller, animated=True)
        split.fit_list()

    def close(self):
        if self in _open_pages:
            _open_pages.remove(self)
        nav = self.controller.navigationController
        if nav is None:
            return
        stack = list(nav.viewControllers)
        index = stack.index(self.controller)
        split = _split(self.app)
        if index == 0:  # the device page beside the list: none any more
            nav.setViewControllers([split.empty], animated=False)
            split.deselect()
        else:  # this page, and any pushed over it
            nav.popToViewController(stack[index - 1], animated=True)
        split.fit_list()


class _Split:
    """The iPad's two columns: the window's own navigation controller (the device list) at the
    left, and at the right `detail`, a navigation controller holding the device page (or a note
    that none is open) with the other pages pushed over it. While one of those is open the list
    waits, dimmed, as on an iPhone, where it's under the page."""
    WIDTH = (390, 0.36, 440)  # the list's column: at least (Quick Scan, Full Scan and Stop fit), share, at most

    def __init__(self, app):
        self.app, self.view, self.detail, self.empty = app, None, None, None

    def _build(self):
        UIColor = _objc("UIColor")
        self.empty = _objc("UIViewController").alloc().init()
        self.empty.view.backgroundColor = _class_value(UIColor, "systemBackgroundColor")
        try:  # iOS 17 and later
            note = _objc("UIContentUnavailableConfiguration").emptyConfiguration()
            note.image = _objc("UIImage").systemImageNamed("network")
            note.text = "No Device Selected"
            note.secondaryText = "Run a Quick Scan or a Full Scan, then pick a device from the list."
            self.empty.contentUnavailableConfiguration = note
        except Exception:
            pass
        self.detail = _objc("UINavigationController").alloc().initWithRootViewController(self.empty)
        self.detail.delegate = _nav_watcher()
        split = _objc("UISplitViewController").alloc().initWithStyle(1)  # double column
        split.preferredSplitBehavior = 1  # tile: side by side, never one over the other
        split.preferredDisplayMode = 2  # one beside the secondary
        split.presentsWithGesture = False
        split.displayModeButtonVisibility = 1  # never: no button that hides the list
        split.primaryBackgroundStyle = 0  # none: a sidebar's glass let the wallpaper through in dark mode
        split.minimumPrimaryColumnWidth, split.maximumPrimaryColumnWidth = self.WIDTH[0], self.WIDTH[2]
        split.preferredPrimaryColumnWidthFraction = self.WIDTH[1]
        self.stand_in = _objc("UIViewController").alloc().init()  # the left column while the list isn't in it
        split.setViewController(self.stand_in, forColumn=0)
        split.setViewController(self.detail, forColumn=2)
        self.split = split

    def arrange(self):
        """Side by side at a regular width, the iPhone's layout at a compact one (iPad only)."""
        if not _pad():
            return
        size_class = self.app.main_window._impl.native.traitCollection.horizontalSizeClass
        if not size_class:  # not known before the window is on screen: asked again then
            return
        wide = size_class == 2  # regular
        try:
            if wide and self.view is None:
                self._expand()
            elif not wide and self.view is not None:
                self._collapse()
        except Exception:  # the layout stays as it was rather than the app stopping
            import traceback
            self.app._append_log("Couldn't change the iPad layout:\n" + traceback.format_exc(), status=False)

    def _expand(self):
        global _moving
        if self.detail is None:
            self._build()
        nav = _phone_nav(self.app)
        stack = list(nav.viewControllers)
        pages = stack[1:]
        page = getattr(self.app, "page", None)
        if not pages or page is None or pages[0] != page.controller:
            pages.insert(0, self.empty)
        _moving = True
        try:
            nav.setViewControllers(stack[:1], animated=False)
            self.detail.setViewControllers(pages, animated=False)
            # The window lets go of the list's controller first: UIKit won't put a window's
            # root controller in a column.
            self.app.main_window._impl.native.rootViewController = self.split
            self.split.setViewController(nav, forColumn=0)
            self.view = self.split
        finally:
            _moving = False
        self.fit_list()

    def _collapse(self):
        global _moving
        nav = _phone_nav(self.app)
        pages = [vc for vc in self.detail.viewControllers if vc != self.empty]
        _moving = True
        try:
            self.detail.setViewControllers([self.empty], animated=False)
            self.split.setViewController(self.stand_in, forColumn=0)
            self.app.main_window._impl.native.rootViewController = nav
            nav.setViewControllers([nav.viewControllers[0], *pages], animated=False)
            self.view = None
        finally:
            _moving = False
        self.fit_list()

    def fit_list(self):
        """The list waits, dimmed, while a page is open over the device page beside it; the line
        at its edge shows while there's a page beside it."""
        waiting = self.view is not None and len(list(self.detail.viewControllers)) > 1
        view = _phone_nav(self.app).view
        view.userInteractionEnabled = not waiting
        view.alpha = 0.45 if waiting else 1.0
        if getattr(self.app, "_ios_edge", None) is not None:
            self.app._ios_edge.hidden = self.view is None

    def deselect(self):
        native = self.app.table._impl.native
        path = native.indexPathForSelectedRow
        if path is not None:
            native.deselectRowAtIndexPath(path, animated=True)


def _pad() -> bool:
    return _objc("UIDevice").currentDevice.userInterfaceIdiom == 1  # UIUserInterfaceIdiomPad


def _split(app) -> _Split:
    if not hasattr(app, "_ios_split"):
        app._ios_split = _Split(app)
    return app._ios_split


def side_by_side(app) -> bool:
    """True while the device list stays in view beside the pages (an iPad at a regular width)."""
    return _split(app).view is not None


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
        for label in app.status.widgets:  # the list's status line and Tools'
            _shortened(label)
    except Exception:
        pass  # cosmetic
    if _pad():
        _fit_pad(app)


def _fit_pad(app):
    """iPad: the list beside the pages at a regular width (_Split), following the window's width
    from then on; the device page's tabs along the bottom as on an iPhone (iPadOS puts them at the
    top, over the page, with Notes and Log behind an arrow); the list's column in the page's
    background colour, with a line between them."""
    from rubicon.objc import Block, objc_id
    try:
        app.tabs._impl.native_controller.traitOverrides.horizontalSizeClass = 1  # compact
        UIColor, view = _objc("UIColor"), _phone_nav(app).view
        view.backgroundColor = _class_value(UIColor, "systemBackgroundColor")
        # A hairline down the list's right-hand edge, where the page beside it begins.
        from rubicon.objc import CGRect
        width = 1 / _class_value(_objc("UIScreen"), "mainScreen").scale
        size = view.bounds.size
        line = _objc("UIView").alloc().initWithFrame(CGRect((size.width - width, 0), (width, size.height)))
        line.backgroundColor = _class_value(UIColor, "separatorColor")
        line.autoresizingMask = 1 | 16  # flexible left margin and height: it stays at the edge
        line.hidden = True
        view.addSubview(line)
        app._ios_edge = line
    except Exception:
        pass  # cosmetic
    split = _split(app)
    split.arrange()

    def changed(environment, previous) -> None:
        app.loop.call_soon(split.arrange)  # after UIKit's own changes for the new width

    try:  # iOS 17 and later; fit_safe_area arranges after every resize too
        app._ios_trait_block = Block(changed, None, objc_id, objc_id)
        app._ios_trait_watch = app.main_window._impl.native.registerForTraitChanges(
            _objc("NSArray").arrayWithObject(_objc("UITraitHorizontalSizeClass")), withHandler=app._ios_trait_block)
    except Exception:
        pass


def _shortened(label):
    """A one-line label that ends in … where its text doesn't fit: Toga makes a label at least
    as wide as its text, which pushed the end of a long status past the screen's edge."""
    from travertino.size import at_least
    impl = label._impl
    rehint = impl.rehint

    def shortening():
        rehint()
        label.intrinsic.width = at_least(0)

    impl.rehint = shortening
    impl.native.lineBreakMode = 4  # NSLineBreakByTruncatingTail
    label.refresh()


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
    turned sideways, the camera cutout): Toga lays it out to the very edges. On an iPad, the
    list beside the pages or not, for the window's new width."""
    if _pad():
        _split(app).arrange()
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


def watch_keyboard(app, widget, follow: bool = True):
    """Keep a text view clear of the on-screen keyboard while it's up: the part it covers can be
    scrolled into view. follow: show its last lines (the SSH session's console, as commands are
    typed under it); otherwise the text being edited stays where it is (the config editor)."""
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
            if follow:
                widget.scroll_to_bottom()
            elif view.isFirstResponder() and covered:  # the line being edited comes out from under it
                view.scrollRangeToVisible(view.selectedRange)

        if not hasattr(app, "_keyboard_watchers"):
            app._keyboard_watchers = []  # (block, observer) for each view, kept alive
        block = Block(moved, None, objc_id)
        app._keyboard_watchers.append((block, center.addObserverForName(
            "UIKeyboardWillChangeFrameNotification", object=None, queue=None, usingBlock=block)))
    except Exception:
        pass  # the console still scrolls by hand


def plain_entry(widget, send: bool = False, new_password: bool = False):
    """A text field for usernames, passwords, ports and shell commands: no capital first letter,
    no corrections, no smart quotes; send: its return key reads "send". new_password: a new
    password for a device, which iOS mustn't take over with a "strong password" of its own (that
    blanks the field and swallows typing): marked as a one-time code instead. (Set through the
    setters: rubicon doesn't find UITextInputTraits' properties on a UITextField.)"""
    native = widget._impl.native
    if new_password:
        try:
            from rubicon.objc import send_message, objc_id
            from rubicon.objc.api import ns_from_py
            send_message(native, "setTextContentType:", ns_from_py("one-time-code"), restype=None,
                         argtypes=[objc_id])
            native.passwordRules = None
        except Exception:
            pass
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


def done_bar(app, widget):
    """A Done button above the keyboard for a text view that takes many lines (the config
    editor), where Return is a new line: Done puts the keyboard away. Dragging the text down
    does too."""
    try:
        from rubicon.objc import Block, objc_id
        if not hasattr(app, "_done_blocks"):
            app._done_blocks = []  # kept alive
        block = Block(lambda action: end_editing(app), None, objc_id)
        app._done_blocks.append(block)
        UIBarButtonItem = _objc("UIBarButtonItem")
        done = _objc("UIAction").actionWithTitle("Done", image=None, identifier=None, handler=block)
        bar = _objc("UIToolbar").alloc().init()
        bar.items = _objc("NSArray").arrayWithArray([UIBarButtonItem.flexibleSpaceItem(),
                                                     UIBarButtonItem.alloc().initWithPrimaryAction(done)])
        bar.sizeToFit()
        native = widget._impl.native
        native.inputAccessoryView = bar
        native.keyboardDismissMode = 2  # UIScrollViewKeyboardDismissModeInteractive
    except Exception:
        pass
