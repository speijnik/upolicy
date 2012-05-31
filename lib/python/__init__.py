# upolicy/__init__.py
#
# Copyright (C) 2012 Stephan Peijnik <stephan@peijnik.at>
#
# This file is part of upolicy.
#
#  upolicy is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  upolicy is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with upolicy.  If not, see <http://www.gnu.org/licenses/>.

import logging

import _upolicy

__all__ = ['__version__', 'BaseException', 'InitException', 
           'ContextCreateException', 'Context', 'initialize',
           'cleanup', 'is_initialized', 'join', 'version', 'Decision'] 
           

__version__ = '%d.%d.%d' % (_upolicy.version())

BaseException = _upolicy.BaseException
InitException = _upolicy.InitException
ContextCreateException = _upolicy.ContextCreateException

EventInfo = _upolicy.EventInfo
LOGGER_NAME = _upolicy.LOGGER_NAME
Logger = logging.getLogger(LOGGER_NAME)

def initialize():
    """ Initialize upolicy """
    if not _upolicy.is_initialized():
        return _upolicy.initialize()
    return True

def cleanup():
    """ Finalize upolicy """
    if _upolicy.is_initialized():
        return _upolicy.cleanup()
    return True

def is_initialized():
    """ Check whether upolicy has been initialized already. """
    return _upolicy.is_initialized()

def join():
    """ Wait for all running tracees to exit. """
    return _upolicy.join()

def version():
    """ Return tuple of major, minor and patch version of upolicy """
    return _upolicy.version()

class Decision(object):
    """ Decision constants """
    
    ALLOW = _upolicy.ALLOW
    DENY = _upolicy.DENY
    KILL = _upolicy.KILL

def subscribe(typ, *events):
    """ Decorator which defines Context event callback methods.
    
    :param typ: Subscription type (notification or event)
    :type typ: str
    :param *events: Tuple of event names
    :type *events: tuple(str)
    """
    
    if typ not in ('notification', 'question'):
        raise ValueError('Type must be either notification or question')
    
    def __subscribe(f):
        # generate the marker object
        setattr(f, '_upolicy_', { '_events_': events, '_type_': typ })
        return f
    
    return __subscribe

def subscribe_notification(*events):
    """ Shortcut for subscribe('notification', *events) """
    return subscribe('notification', *events)

def subscribe_question(*events):
    """ Shortcut for subscribe('question', *events) """
    return subscribe('question', *events)

class Context(_upolicy.Context):
    """ Context """
    
    def __init__(self):
        """ Constructor """
        questions = dict()
        notifications = dict()
        for m_name in dir(self):
            m = getattr(self, m_name, None)
            Logger.debug('Checking member %s (%r)', m_name, m)
            info = getattr(m, '_upolicy_', None)
            Logger.debug('info=%r', info)
            if info and callable(m) and info.has_key('_type_') and info.has_key('_events_'):
                typ = info['_type_']
                events = info['_events_']
                Logger.debug('typ=%s,events=%r (type(events)=%r)', typ, events, type(events))
                Logger.debug('type(m)=%r', type(m))
                if events and typ and type(events) is tuple:
                    dest = None
                    if typ == 'notification':
                        dest = notifications
                    elif typ == 'question':
                        dest = questions
                    else:
                        Logger.debug('Invalid type %s.', typ)
                        continue
                    
                    for ev in events:
                        if not ev in dest.keys():
                            Logger.debug('Installed %r', ev)
                            dest[ev] = m
                    
        _upolicy.Context.__init__(self, questions = questions, 
                                  notifications = notifications)
        
    def __repr__(self):
        return '<upolicy.Context id=%d>' % (self.id)
                    
                
                
