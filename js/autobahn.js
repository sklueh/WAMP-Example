/** @license AutobahnJS - http://autobahn.ws
 *
 * Copyright 2011, 2012 Tavendo GmbH.
 * Licensed under the MIT License.
 * See license text at http://www.opensource.org/licenses/mit-license.php
 *
 * AutobahnJS includes code from:
 *
 * when - http://cujojs.com
 *
 * (c) copyright B Cavalier & J Hann
 * Licensed under the MIT License at:
 * http://www.opensource.org/licenses/mit-license.php
 *
 * Crypto-JS - http://code.google.com/p/crypto-js/
 *
 * (c) 2009-2012 by Jeff Mott. All rights reserved.
 * Licensed under the New BSD License at:
 * http://code.google.com/p/crypto-js/wiki/License
 */

/** @license MIT License (c) copyright B Cavalier & J Hann */

/**
 * when
 * A lightweight CommonJS Promises/A and when() implementation
 *
 * when is part of the cujo.js family of libraries (http://cujojs.com/)
 *
 * Licensed under the MIT License at:
 * http://www.opensource.org/licenses/mit-license.php
 *
 * @version 1.0.4
 */

(function(define) {
define(function() {
    var freeze, reduceArray, undef;

    /**
     * No-Op function used in method replacement
     * @private
     */
    function noop() {}

    /**
     * Allocate a new Array of size n
     * @private
     * @param n {number} size of new Array
     * @returns {Array}
     */
    function allocateArray(n) {
        return new Array(n);
    }

    /**
     * Use freeze if it exists
     * @function
     * @private
     */
    freeze = Object.freeze || function(o) { return o; };

    // ES5 reduce implementation if native not available
    // See: http://es5.github.com/#x15.4.4.21 as there are many
    // specifics and edge cases.
    reduceArray = [].reduce ||
        function(reduceFunc /*, initialValue */) {
            // ES5 dictates that reduce.length === 1

            // This implementation deviates from ES5 spec in the following ways:
            // 1. It does not check if reduceFunc is a Callable

            var arr, args, reduced, len, i;

            i = 0;
            arr = Object(this);
            len = arr.length >>> 0;
            args = arguments;

            // If no initialValue, use first item of array (we know length !== 0 here)
            // and adjust i to start at second item
            if(args.length <= 1) {
                // Skip to the first real element in the array
                for(;;) {
                    if(i in arr) {
                        reduced = arr[i++];
                        break;
                    }

                    // If we reached the end of the array without finding any real
                    // elements, it's a TypeError
                    if(++i >= len) {
                        throw new TypeError();
                    }
                }
            } else {
                // If initialValue provided, use it
                reduced = args[1];
            }

            // Do the actual reduce
            for(;i < len; ++i) {
                // Skip holes
                if(i in arr)
                    reduced = reduceFunc(reduced, arr[i], i, arr);
            }

            return reduced;
        };

    /**
     * Trusted Promise constructor.  A Promise created from this constructor is
     * a trusted when.js promise.  Any other duck-typed promise is considered
     * untrusted.
     */
    function Promise() {}

    /**
     * Create an already-resolved promise for the supplied value
     * @private
     *
     * @param value anything
     * @return {Promise}
     */
    function resolved(value) {

        var p = new Promise();

        p.then = function(callback) {
            checkCallbacks(arguments);

            var nextValue;
            try {
                if(callback) nextValue = callback(value);
                return promise(nextValue === undef ? value : nextValue);
            } catch(e) {
                return rejected(e);
            }
        };

        return freeze(p);
    }

    /**
     * Create an already-rejected {@link Promise} with the supplied
     * rejection reason.
     * @private
     *
     * @param reason rejection reason
     * @return {Promise}
     */
    function rejected(reason) {

        var p = new Promise();

        p.then = function(callback, errback) {
            checkCallbacks(arguments);

            var nextValue;
            try {
                if(errback) {
                    nextValue = errback(reason);
                    return promise(nextValue === undef ? reason : nextValue)
                }

                return rejected(reason);

            } catch(e) {
                return rejected(e);
            }
        };

        return freeze(p);
    }

    /**
     * Helper that checks arrayOfCallbacks to ensure that each element is either
     * a function, or null or undefined.
     *
     * @param arrayOfCallbacks {Array} array to check
     * @throws {Error} if any element of arrayOfCallbacks is something other than
     * a Functions, null, or undefined.
     */
    function checkCallbacks(arrayOfCallbacks) {
        var arg, i = arrayOfCallbacks.length;
        while(i) {
            arg = arrayOfCallbacks[--i];
            if (arg != null && typeof arg != 'function') throw new Error('callback is not a function');
        }
    }

    /**
     * Creates a new, CommonJS compliant, Deferred with fully isolated
     * resolver and promise parts, either or both of which may be given out
     * safely to consumers.
     * The Deferred itself has the full API: resolve, reject, progress, and
     * then. The resolver has resolve, reject, and progress.  The promise
     * only has then.
     *
     * @memberOf when
     * @function
     *
     * @returns {Deferred}
     */
    function defer() {
        var deferred, promise, listeners, progressHandlers, _then, _progress, complete;

        listeners = [];
        progressHandlers = [];

        /**
         * Pre-resolution then() that adds the supplied callback, errback, and progback
         * functions to the registered listeners
         *
         * @private
         *
         * @param [callback] {Function} resolution handler
         * @param [errback] {Function} rejection handler
         * @param [progback] {Function} progress handler
         *
         * @throws {Error} if any argument is not null, undefined, or a Function
         */
        _then = function unresolvedThen(callback, errback, progback) {
            // Check parameters and fail immediately if any supplied parameter
            // is not null/undefined and is also not a function.
            // That is, any non-null/undefined parameter must be a function.
            checkCallbacks(arguments);

            var deferred = defer();

            listeners.push(function(promise) {
                promise.then(callback, errback)
                    .then(deferred.resolve, deferred.reject, deferred.progress);
            });

            progback && progressHandlers.push(progback);

            return deferred.promise;
        };

        /**
         * Registers a handler for this {@link Deferred}'s {@link Promise}.  Even though all arguments
         * are optional, each argument that *is* supplied must be null, undefined, or a Function.
         * Any other value will cause an Error to be thrown.
         *
         * @memberOf Promise
         *
         * @param [callback] {Function} resolution handler
         * @param [errback] {Function} rejection handler
         * @param [progback] {Function} progress handler
         *
         * @throws {Error} if any argument is not null, undefined, or a Function
         */
        function then(callback, errback, progback) {
            return _then(callback, errback, progback);
        }

        /**
         * Resolves this {@link Deferred}'s {@link Promise} with val as the
         * resolution value.
         *
         * @memberOf Resolver
         *
         * @param val anything
         */
        function resolve(val) {
            complete(resolved(val));
        }

        /**
         * Rejects this {@link Deferred}'s {@link Promise} with err as the
         * reason.
         *
         * @memberOf Resolver
         *
         * @param err anything
         */
        function reject(err) {
            complete(rejected(err));
        }

        /**
         * @private
         * @param update
         */
        _progress = function(update) {
            var progress, i = 0;
            while (progress = progressHandlers[i++]) progress(update);
        };

        /**
         * Emits a progress update to all progress observers registered with
         * this {@link Deferred}'s {@link Promise}
         *
         * @memberOf Resolver
         *
         * @param update anything
         */
        function progress(update) {
            _progress(update);
        }

        /**
         * Transition from pre-resolution state to post-resolution state, notifying
         * all listeners of the resolution or rejection
         *
         * @private
         *
         * @param completed {Promise} the completed value of this deferred
         */
        complete = function(completed) {
            var listener, i = 0;

            // Replace _then with one that directly notifies with the result.
            _then = completed.then;

            // Replace complete so that this Deferred can only be completed
            // once. Also Replace _progress, so that subsequent attempts to issue
            // progress throw.
            complete = _progress = function alreadyCompleted() {
                // TODO: Consider silently returning here so that parties who
                // have a reference to the resolver cannot tell that the promise
                // has been resolved using try/catch
                throw new Error("already completed");
            };

            // Free progressHandlers array since we'll never issue progress events
            // for this promise again now that it's completed
            progressHandlers = undef;

            // Notify listeners
            // Traverse all listeners registered directly with this Deferred

            while (listener = listeners[i++]) {
                listener(completed);
            }

            listeners = [];
        };

        /**
         * The full Deferred object, with both {@link Promise} and {@link Resolver}
         * parts
         * @class Deferred
         * @name Deferred
         * @augments Resolver
         * @augments Promise
         */
        deferred = {};

        // Promise and Resolver parts
        // Freeze Promise and Resolver APIs

        /**
         * The Promise API
         * @namespace Promise
         * @name Promise
         */
        promise = new Promise();
        promise.then = deferred.then = then;

        /**
         * The {@link Promise} for this {@link Deferred}
         * @memberOf Deferred
         * @name promise
         * @type {Promise}
         */
        deferred.promise = freeze(promise);

        /**
         * The {@link Resolver} for this {@link Deferred}
         * @namespace Resolver
         * @name Resolver
         * @memberOf Deferred
         * @name resolver
         * @type {Resolver}
         */
        deferred.resolver = freeze({
            resolve:  (deferred.resolve  = resolve),
            reject:   (deferred.reject   = reject),
            progress: (deferred.progress = progress)
        });

        return deferred;
    }

    /**
     * Determines if promiseOrValue is a promise or not.  Uses the feature
     * test from http://wiki.commonjs.org/wiki/Promises/A to determine if
     * promiseOrValue is a promise.
     *
     * @param promiseOrValue anything
     *
     * @returns {Boolean} true if promiseOrValue is a {@link Promise}
     */
    function isPromise(promiseOrValue) {
        return promiseOrValue && typeof promiseOrValue.then === 'function';
    }

    /**
     * Register an observer for a promise or immediate value.
     *
     * @function
     * @name when
     * @namespace
     *
     * @param promiseOrValue anything
     * @param {Function} [callback] callback to be called when promiseOrValue is
     *   successfully resolved.  If promiseOrValue is an immediate value, callback
     *   will be invoked immediately.
     * @param {Function} [errback] callback to be called when promiseOrValue is
     *   rejected.
     * @param {Function} [progressHandler] callback to be called when progress updates
     *   are issued for promiseOrValue.
     *
     * @returns {Promise} a new {@link Promise} that will complete with the return
     *   value of callback or errback or the completion value of promiseOrValue if
     *   callback and/or errback is not supplied.
     */
    function when(promiseOrValue, callback, errback, progressHandler) {
        // Get a promise for the input promiseOrValue
        // See promise()
        var trustedPromise = promise(promiseOrValue);

        // Register promise handlers
        return trustedPromise.then(callback, errback, progressHandler);
    }

    /**
     * Returns promiseOrValue if promiseOrValue is a {@link Promise}, a new Promise if
     * promiseOrValue is a foreign promise, or a new, already-resolved {@link Promise}
     * whose resolution value is promiseOrValue if promiseOrValue is an immediate value.
     *
     * Note that this function is not safe to export since it will return its
     * input when promiseOrValue is a {@link Promise}
     *
     * @private
     *
     * @param promiseOrValue anything
     *
     * @returns Guaranteed to return a trusted Promise.  If promiseOrValue is a when.js {@link Promise}
     *   returns promiseOrValue, otherwise, returns a new, already-resolved, when.js {@link Promise}
     *   whose resolution value is:
     *   * the resolution value of promiseOrValue if it's a foreign promise, or
     *   * promiseOrValue if it's a value
     */
    function promise(promiseOrValue) {
        var promise, deferred;

        if(promiseOrValue instanceof Promise) {
            // It's a when.js promise, so we trust it
            promise = promiseOrValue;

        } else {
            // It's not a when.js promise.  Check to see if it's a foreign promise
            // or a value.

            deferred = defer();
            if(isPromise(promiseOrValue)) {
                // It's a compliant promise, but we don't know where it came from,
                // so we don't trust its implementation entirely.  Introduce a trusted
                // middleman when.js promise

                // IMPORTANT: This is the only place when.js should ever call .then() on
                // an untrusted promise.
                promiseOrValue.then(deferred.resolve, deferred.reject, deferred.progress);
                promise = deferred.promise;

            } else {
                // It's a value, not a promise.  Create an already-resolved promise
                // for it.
                deferred.resolve(promiseOrValue);
                promise = deferred.promise;
            }
        }

        return promise;
    }

    /**
     * Return a promise that will resolve when howMany of the supplied promisesOrValues
     * have resolved. The resolution value of the returned promise will be an array of
     * length howMany containing the resolutions values of the triggering promisesOrValues.
     *
     * @memberOf when
     *
     * @param promisesOrValues {Array} array of anything, may contain a mix
     *      of {@link Promise}s and values
     * @param howMany
     * @param [callback]
     * @param [errback]
     * @param [progressHandler]
     *
     * @returns {Promise}
     */
    function some(promisesOrValues, howMany, callback, errback, progressHandler) {
        var toResolve, results, ret, deferred, resolver, rejecter, handleProgress, len, i;

        len = promisesOrValues.length >>> 0;

        toResolve = Math.max(0, Math.min(howMany, len));
        results = [];
        deferred = defer();
        ret = when(deferred, callback, errback, progressHandler);

        // Wrapper so that resolver can be replaced
        function resolve(val) {
            resolver(val);
        }

        // Wrapper so that rejecter can be replaced
        function reject(err) {
            rejecter(err);
        }

        // Wrapper so that progress can be replaced
        function progress(update) {
            handleProgress(update);
        }

        function complete() {
            resolver = rejecter = handleProgress = noop;
        }

        // No items in the input, resolve immediately
        if (!toResolve) {
            deferred.resolve(results);

        } else {
            // Resolver for promises.  Captures the value and resolves
            // the returned promise when toResolve reaches zero.
            // Overwrites resolver var with a noop once promise has
            // be resolved to cover case where n < promises.length
            resolver = function(val) {
                // This orders the values based on promise resolution order
                // Another strategy would be to use the original position of
                // the corresponding promise.
                results.push(val);

                if (!--toResolve) {
                    complete();
                    deferred.resolve(results);
                }
            };

            // Rejecter for promises.  Rejects returned promise
            // immediately, and overwrites rejecter var with a noop
            // once promise to cover case where n < promises.length.
            // TODO: Consider rejecting only when N (or promises.length - N?)
            // promises have been rejected instead of only one?
            rejecter = function(err) {
                complete();
                deferred.reject(err);
            };

            handleProgress = deferred.progress;

            // TODO: Replace while with forEach
            for(i = 0; i < len; ++i) {
                if(i in promisesOrValues) {
                    when(promisesOrValues[i], resolve, reject, progress);
                }
            }
        }

        return ret;
    }

    /**
     * Return a promise that will resolve only once all the supplied promisesOrValues
     * have resolved. The resolution value of the returned promise will be an array
     * containing the resolution values of each of the promisesOrValues.
     *
     * @memberOf when
     *
     * @param promisesOrValues {Array} array of anything, may contain a mix
     *      of {@link Promise}s and values
     * @param [callback] {Function}
     * @param [errback] {Function}
     * @param [progressHandler] {Function}
     *
     * @returns {Promise}
     */
    function all(promisesOrValues, callback, errback, progressHandler) {
        var results, promise;

        results = allocateArray(promisesOrValues.length);
        promise = reduce(promisesOrValues, reduceIntoArray, results);

        return when(promise, callback, errback, progressHandler);
    }

    function reduceIntoArray(current, val, i) {
        current[i] = val;
        return current;
    }

    /**
     * Return a promise that will resolve when any one of the supplied promisesOrValues
     * has resolved. The resolution value of the returned promise will be the resolution
     * value of the triggering promiseOrValue.
     *
     * @memberOf when
     *
     * @param promisesOrValues {Array} array of anything, may contain a mix
     *      of {@link Promise}s and values
     * @param [callback] {Function}
     * @param [errback] {Function}
     * @param [progressHandler] {Function}
     *
     * @returns {Promise}
     */
    function any(promisesOrValues, callback, errback, progressHandler) {

        function unwrapSingleResult(val) {
            return callback(val[0]);
        }

        return some(promisesOrValues, 1, unwrapSingleResult, errback, progressHandler);
    }

    /**
     * Traditional map function, similar to `Array.prototype.map()`, but allows
     * input to contain {@link Promise}s and/or values, and mapFunc may return
     * either a value or a {@link Promise}
     *
     * @memberOf when
     *
     * @param promisesOrValues {Array} array of anything, may contain a mix
     *      of {@link Promise}s and values
     * @param mapFunc {Function} mapping function mapFunc(value) which may return
     *      either a {@link Promise} or value
     *
     * @returns {Promise} a {@link Promise} that will resolve to an array containing
     *      the mapped output values.
     */
    function map(promisesOrValues, mapFunc) {

        var results, i;

        // Since we know the resulting length, we can preallocate the results
        // array to avoid array expansions.
        i = promisesOrValues.length;
        results = allocateArray(i);

        // Since mapFunc may be async, get all invocations of it into flight
        // asap, and then use reduce() to collect all the results
        for(;i >= 0; --i) {
            if(i in promisesOrValues)
                results[i] = when(promisesOrValues[i], mapFunc);
        }

        // Could use all() here, but that would result in another array
        // being allocated, i.e. map() would end up allocating 2 arrays
        // of size len instead of just 1.  Since all() uses reduce()
        // anyway, avoid the additional allocation by calling reduce
        // directly.
        return reduce(results, reduceIntoArray, results);
    }

    /**
     * Traditional reduce function, similar to `Array.prototype.reduce()`, but
     * input may contain {@link Promise}s and/or values, but reduceFunc
     * may return either a value or a {@link Promise}, *and* initialValue may
     * be a {@link Promise} for the starting value.
     *
     * @memberOf when
     *
     * @param promisesOrValues {Array} array of anything, may contain a mix
     *      of {@link Promise}s and values
     * @param reduceFunc {Function} reduce function reduce(currentValue, nextValue, index, total),
     *      where total is the total number of items being reduced, and will be the same
     *      in each call to reduceFunc.
     * @param initialValue starting value, or a {@link Promise} for the starting value
     *
     * @returns {Promise} that will resolve to the final reduced value
     */
    function reduce(promisesOrValues, reduceFunc, initialValue) {

        var total, args;

        total = promisesOrValues.length;

        // Skip promisesOrValues, since it will be used as 'this' in the call
        // to the actual reduce engine below.

        // Wrap the supplied reduceFunc with one that handles promises and then
        // delegates to the supplied.

        args = [
            function (current, val, i) {
                return when(current, function (c) {
                    return when(val, function (value) {
                        return reduceFunc(c, value, i, total);
                    });
                });
            }
        ];

        if (arguments.length >= 3) args.push(initialValue);

        return promise(reduceArray.apply(promisesOrValues, args));
    }

    /**
     * Ensure that resolution of promiseOrValue will complete resolver with the completion
     * value of promiseOrValue, or instead with resolveValue if it is provided.
     *
     * @memberOf when
     *
     * @param promiseOrValue
     * @param resolver {Resolver}
     * @param [resolveValue] anything
     *
     * @returns {Promise}
     */
    function chain(promiseOrValue, resolver, resolveValue) {
        var useResolveValue = arguments.length > 2;

        return when(promiseOrValue,
            function(val) {
				if(useResolveValue) val = resolveValue;
                resolver.resolve(val);
				return val;
            },
			function(e) {
				resolver.reject(e);
				return rejected(e);
			},
            resolver.progress
        );
    }

    //
    // Public API
    //

    when.defer     = defer;

    when.isPromise = isPromise;
    when.some      = some;
    when.all       = all;
    when.any       = any;

    when.reduce    = reduce;
    when.map       = map;

    when.chain     = chain;

    return when;
});
})(typeof define == 'function'
    ? define
    : function (factory) { typeof module != 'undefined'
        ? (module.exports = factory())
        : (this.when      = factory());
    }
    // Boilerplate for AMD, Node, and browser global
);

/*
 * Crypto-JS v2.5.3
 * http://code.google.com/p/crypto-js/
 * (c) 2009-2012 by Jeff Mott. All rights reserved.
 * http://code.google.com/p/crypto-js/wiki/License
 */
if (typeof Crypto == "undefined" || ! Crypto.util)
{
(function(){

var base64map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Global Crypto object
var Crypto = window.Crypto = {};

// Crypto utilities
var util = Crypto.util = {

	// Bit-wise rotate left
	rotl: function (n, b) {
		return (n << b) | (n >>> (32 - b));
	},

	// Bit-wise rotate right
	rotr: function (n, b) {
		return (n << (32 - b)) | (n >>> b);
	},

	// Swap big-endian to little-endian and vice versa
	endian: function (n) {

		// If number given, swap endian
		if (n.constructor == Number) {
			return util.rotl(n,  8) & 0x00FF00FF |
			       util.rotl(n, 24) & 0xFF00FF00;
		}

		// Else, assume array and swap all items
		for (var i = 0; i < n.length; i++)
			n[i] = util.endian(n[i]);
		return n;

	},

	// Generate an array of any length of random bytes
	randomBytes: function (n) {
		for (var bytes = []; n > 0; n--)
			bytes.push(Math.floor(Math.random() * 256));
		return bytes;
	},

	// Convert a byte array to big-endian 32-bit words
	bytesToWords: function (bytes) {
		for (var words = [], i = 0, b = 0; i < bytes.length; i++, b += 8)
			words[b >>> 5] |= (bytes[i] & 0xFF) << (24 - b % 32);
		return words;
	},

	// Convert big-endian 32-bit words to a byte array
	wordsToBytes: function (words) {
		for (var bytes = [], b = 0; b < words.length * 32; b += 8)
			bytes.push((words[b >>> 5] >>> (24 - b % 32)) & 0xFF);
		return bytes;
	},

	// Convert a byte array to a hex string
	bytesToHex: function (bytes) {
		for (var hex = [], i = 0; i < bytes.length; i++) {
			hex.push((bytes[i] >>> 4).toString(16));
			hex.push((bytes[i] & 0xF).toString(16));
		}
		return hex.join("");
	},

	// Convert a hex string to a byte array
	hexToBytes: function (hex) {
		for (var bytes = [], c = 0; c < hex.length; c += 2)
			bytes.push(parseInt(hex.substr(c, 2), 16));
		return bytes;
	},

	// Convert a byte array to a base-64 string
	bytesToBase64: function (bytes) {

		// Use browser-native function if it exists
		if (typeof btoa == "function") return btoa(Binary.bytesToString(bytes));

		for(var base64 = [], i = 0; i < bytes.length; i += 3) {
			var triplet = (bytes[i] << 16) | (bytes[i + 1] << 8) | bytes[i + 2];
			for (var j = 0; j < 4; j++) {
				if (i * 8 + j * 6 <= bytes.length * 8)
					base64.push(base64map.charAt((triplet >>> 6 * (3 - j)) & 0x3F));
				else base64.push("=");
			}
		}

		return base64.join("");

	},

	// Convert a base-64 string to a byte array
	base64ToBytes: function (base64) {

		// Use browser-native function if it exists
		if (typeof atob == "function") return Binary.stringToBytes(atob(base64));

		// Remove non-base-64 characters
		base64 = base64.replace(/[^A-Z0-9+\/]/ig, "");

		for (var bytes = [], i = 0, imod4 = 0; i < base64.length; imod4 = ++i % 4) {
			if (imod4 == 0) continue;
			bytes.push(((base64map.indexOf(base64.charAt(i - 1)) & (Math.pow(2, -2 * imod4 + 8) - 1)) << (imod4 * 2)) |
			           (base64map.indexOf(base64.charAt(i)) >>> (6 - imod4 * 2)));
		}

		return bytes;

	}

};

// Crypto character encodings
var charenc = Crypto.charenc = {};

// UTF-8 encoding
var UTF8 = charenc.UTF8 = {

	// Convert a string to a byte array
	stringToBytes: function (str) {
		return Binary.stringToBytes(unescape(encodeURIComponent(str)));
	},

	// Convert a byte array to a string
	bytesToString: function (bytes) {
		return decodeURIComponent(escape(Binary.bytesToString(bytes)));
	}

};

// Binary encoding
var Binary = charenc.Binary = {

	// Convert a string to a byte array
	stringToBytes: function (str) {
		for (var bytes = [], i = 0; i < str.length; i++)
			bytes.push(str.charCodeAt(i) & 0xFF);
		return bytes;
	},

	// Convert a byte array to a string
	bytesToString: function (bytes) {
		for (var str = [], i = 0; i < bytes.length; i++)
			str.push(String.fromCharCode(bytes[i]));
		return str.join("");
	}

};

})();
}

/*
 * Crypto-JS v2.5.3
 * http://code.google.com/p/crypto-js/
 * (c) 2009-2012 by Jeff Mott. All rights reserved.
 * http://code.google.com/p/crypto-js/wiki/License
 */
(typeof Crypto=="undefined"||!Crypto.util)&&function(){var d=window.Crypto={},k=d.util={rotl:function(b,a){return b<<a|b>>>32-a},rotr:function(b,a){return b<<32-a|b>>>a},endian:function(b){if(b.constructor==Number)return k.rotl(b,8)&16711935|k.rotl(b,24)&4278255360;for(var a=0;a<b.length;a++)b[a]=k.endian(b[a]);return b},randomBytes:function(b){for(var a=[];b>0;b--)a.push(Math.floor(Math.random()*256));return a},bytesToWords:function(b){for(var a=[],c=0,e=0;c<b.length;c++,e+=8)a[e>>>5]|=(b[c]&255)<<
24-e%32;return a},wordsToBytes:function(b){for(var a=[],c=0;c<b.length*32;c+=8)a.push(b[c>>>5]>>>24-c%32&255);return a},bytesToHex:function(b){for(var a=[],c=0;c<b.length;c++)a.push((b[c]>>>4).toString(16)),a.push((b[c]&15).toString(16));return a.join("")},hexToBytes:function(b){for(var a=[],c=0;c<b.length;c+=2)a.push(parseInt(b.substr(c,2),16));return a},bytesToBase64:function(b){if(typeof btoa=="function")return btoa(g.bytesToString(b));for(var a=[],c=0;c<b.length;c+=3)for(var e=b[c]<<16|b[c+1]<<
8|b[c+2],p=0;p<4;p++)c*8+p*6<=b.length*8?a.push("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(e>>>6*(3-p)&63)):a.push("=");return a.join("")},base64ToBytes:function(b){if(typeof atob=="function")return g.stringToBytes(atob(b));for(var b=b.replace(/[^A-Z0-9+\/]/ig,""),a=[],c=0,e=0;c<b.length;e=++c%4)e!=0&&a.push(("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".indexOf(b.charAt(c-1))&Math.pow(2,-2*e+8)-1)<<e*2|"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".indexOf(b.charAt(c))>>>
6-e*2);return a}},d=d.charenc={};d.UTF8={stringToBytes:function(b){return g.stringToBytes(unescape(encodeURIComponent(b)))},bytesToString:function(b){return decodeURIComponent(escape(g.bytesToString(b)))}};var g=d.Binary={stringToBytes:function(b){for(var a=[],c=0;c<b.length;c++)a.push(b.charCodeAt(c)&255);return a},bytesToString:function(b){for(var a=[],c=0;c<b.length;c++)a.push(String.fromCharCode(b[c]));return a.join("")}}}();
(function(){var d=Crypto,k=d.util,g=d.charenc,b=g.UTF8,a=g.Binary,c=[1116352408,1899447441,3049323471,3921009573,961987163,1508970993,2453635748,2870763221,3624381080,310598401,607225278,1426881987,1925078388,2162078206,2614888103,3248222580,3835390401,4022224774,264347078,604807628,770255983,1249150122,1555081692,1996064986,2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,338241895,666307205,773529912,1294757372,1396182291,1695183700,1986661051,2177026350,2456956037,2730485921,
2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,1747873779,1955562222,2024104815,2227730452,2361852424,2428436474,2756734187,3204031479,3329325298],e=d.SHA256=function(b,c){var f=k.wordsToBytes(e._sha256(b));return c&&c.asBytes?f:c&&c.asString?a.bytesToString(f):k.bytesToHex(f)};e._sha256=function(a){a.constructor==String&&(a=b.stringToBytes(a));var e=k.bytesToWords(a),f=a.length*8,a=[1779033703,3144134277,
1013904242,2773480762,1359893119,2600822924,528734635,1541459225],d=[],g,m,r,i,n,o,s,t,h,l,j;e[f>>5]|=128<<24-f%32;e[(f+64>>9<<4)+15]=f;for(t=0;t<e.length;t+=16){f=a[0];g=a[1];m=a[2];r=a[3];i=a[4];n=a[5];o=a[6];s=a[7];for(h=0;h<64;h++){h<16?d[h]=e[h+t]:(l=d[h-15],j=d[h-2],d[h]=((l<<25|l>>>7)^(l<<14|l>>>18)^l>>>3)+(d[h-7]>>>0)+((j<<15|j>>>17)^(j<<13|j>>>19)^j>>>10)+(d[h-16]>>>0));j=f&g^f&m^g&m;var u=(f<<30|f>>>2)^(f<<19|f>>>13)^(f<<10|f>>>22);l=(s>>>0)+((i<<26|i>>>6)^(i<<21|i>>>11)^(i<<7|i>>>25))+
(i&n^~i&o)+c[h]+(d[h]>>>0);j=u+j;s=o;o=n;n=i;i=r+l>>>0;r=m;m=g;g=f;f=l+j>>>0}a[0]+=f;a[1]+=g;a[2]+=m;a[3]+=r;a[4]+=i;a[5]+=n;a[6]+=o;a[7]+=s}return a};e._blocksize=16;e._digestsize=32})();
(function(){var d=Crypto,k=d.util,g=d.charenc,b=g.UTF8,a=g.Binary;d.HMAC=function(c,e,d,g){e.constructor==String&&(e=b.stringToBytes(e));d.constructor==String&&(d=b.stringToBytes(d));d.length>c._blocksize*4&&(d=c(d,{asBytes:!0}));for(var f=d.slice(0),d=d.slice(0),q=0;q<c._blocksize*4;q++)f[q]^=92,d[q]^=54;c=c(f.concat(c(d.concat(e),{asBytes:!0})),{asBytes:!0});return g&&g.asBytes?c:g&&g.asString?a.bytesToString(c):k.bytesToHex(c)}})();

/** @license MIT License (c) 2011,2012 Copyright Tavendo GmbH. */

/**
 * AutobahnJS - http://autobahn.ws
 *
 * A lightweight implementation of
 *
 *   WAMP (The WebSocket Application Messaging Protocol) - http://wamp.ws
 *
 * Provides asynchronous RPC/PubSub over WebSocket.
 *
 * Copyright 2011, 2012 Tavendo GmbH. Licensed under the MIT License.
 * See license text at http://www.opensource.org/licenses/mit-license.php
 */

"use strict";

/** @define {string} */
var AUTOBAHNJS_VERSION = '?.?.?';

/** @define {boolean} */
var AUTOBAHNJS_DEBUG = true;



var ab = window.ab = {};

ab._version = AUTOBAHNJS_VERSION;

/**
 * Fallbacks for browsers lacking
 *
 *    Array.prototype.indexOf
 *    Array.prototype.forEach
 *
 * most notably MSIE8.
 *
 * Source:
 *    https://developer.mozilla.org/en/JavaScript/Reference/Global_Objects/Array/indexOf
 *    https://developer.mozilla.org/en/JavaScript/Reference/Global_Objects/Array/forEach
 */
(function () {
   if (!Array.prototype.indexOf) {
      Array.prototype.indexOf = function (searchElement /*, fromIndex */ ) {
         "use strict";
         if (this === null) {
            throw new TypeError();
         }
         var t = new Object(this);
         var len = t.length >>> 0;
         if (len === 0) {
            return -1;
         }
         var n = 0;
         if (arguments.length > 0) {
            n = Number(arguments[1]);
            if (n !== n) { // shortcut for verifying if it's NaN
               n = 0;
            } else if (n !== 0 && n !== Infinity && n !== -Infinity) {
               n = (n > 0 || -1) * Math.floor(Math.abs(n));
            }
         }
         if (n >= len) {
            return -1;
         }
         var k = n >= 0 ? n : Math.max(len - Math.abs(n), 0);
         for (; k < len; k++) {
            if (k in t && t[k] === searchElement) {
               return k;
            }
         }
         return -1;
      };
   }

   if (!Array.prototype.forEach) {

      Array.prototype.forEach = function (callback, thisArg) {

         var T, k;

         if (this === null) {
            throw new TypeError(" this is null or not defined");
         }

         // 1. Let O be the result of calling ToObject passing the |this| value as the argument.
         var O = new Object(this);

         // 2. Let lenValue be the result of calling the Get internal method of O with the argument "length".
         // 3. Let len be ToUint32(lenValue).
         var len = O.length >>> 0; // Hack to convert O.length to a UInt32

         // 4. If IsCallable(callback) is false, throw a TypeError exception.
         // See: http://es5.github.com/#x9.11
         if ({}.toString.call(callback) !== "[object Function]") {
            throw new TypeError(callback + " is not a function");
         }

         // 5. If thisArg was supplied, let T be thisArg; else let T be undefined.
         if (thisArg) {
            T = thisArg;
         }

         // 6. Let k be 0
         k = 0;

         // 7. Repeat, while k < len
         while (k < len) {

            var kValue;

            // a. Let Pk be ToString(k).
            //   This is implicit for LHS operands of the in operator
            // b. Let kPresent be the result of calling the HasProperty internal method of O with argument Pk.
            //   This step can be combined with c
            // c. If kPresent is true, then
            if (k in O) {

               // i. Let kValue be the result of calling the Get internal method of O with argument Pk.
               kValue = O[k];

               // ii. Call the Call internal method of callback with T as the this value and
               // argument list containing kValue, k, and O.
               callback.call(T, kValue, k, O);
            }
            // d. Increase k by 1.
            k++;
         }
         // 8. return undefined
      };
   }

})();


// Helper to slice out browser / version from userAgent
ab._sliceUserAgent = function (str, delim, delim2) {
   var ver = [];
   var ua = navigator.userAgent;
   var i = ua.indexOf(str);
   var j = ua.indexOf(delim, i);
   if (j < 0) {
      j = ua.length;
   }
   var agent = ua.slice(i, j).split(delim2);
   var v = agent[1].split('.');
   for (var k = 0; k < v.length; ++k) {
      ver.push(parseInt(v[k], 10));
   }
   return {name: agent[0], version: ver};
};

/**
 * Detect browser and browser version.
 */
ab.getBrowser = function () {

   var ua = navigator.userAgent;
   if (ua.indexOf("Chrome") > -1) {
      return ab._sliceUserAgent("Chrome", " ", "/");
   } else if (ua.indexOf("Safari") > -1) {
      return ab._sliceUserAgent("Safari", " ", "/");
   } else if (ua.indexOf("Firefox") > -1) {
      return ab._sliceUserAgent("Firefox", " ", "/");
   } else if (ua.indexOf("MSIE") > -1) {
      return ab._sliceUserAgent("MSIE", ";", " ");
   } else {
      return null;
   }
};


// Logging message for unsupported browser.
ab.browserNotSupportedMessage = "Browser does not support WebSockets (RFC6455)";


ab._idchars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
ab._idlen = 16;
ab._subprotocol = "wamp";

ab._newid = function () {
   var id = "";
   for (var i = 0; i < ab._idlen; i += 1) {
      id += ab._idchars.charAt(Math.floor(Math.random() * ab._idchars.length));
   }
   return id;
};

ab.log = function (o) {
   if (window.console && console.log) {
      //console.log.apply(console, !!arguments.length ? arguments : [this]);
      if (arguments.length > 1) {
         console.group("Log Item");
         for (var i = 0; i < arguments.length; i += 1) {
            console.log(arguments[i]);
         }
         console.groupEnd();
      } else {
         console.log(arguments[0]);
      }
   }
};

ab._debugrpc = false;
ab._debugpubsub = false;
ab._debugws = false;

ab.debug = function (debugWamp, debugWs) {
   if ("console" in window) {
      ab._debugrpc = debugWamp;
      ab._debugpubsub = debugWamp;
      ab._debugws = debugWs;
   } else {
      throw "browser does not support console object";
   }
};

ab.version = function () {
   return ab._version;
};

ab.PrefixMap = function () {

   var self = this;
   self._index = {};
   self._rindex = {};
};

ab.PrefixMap.prototype.get = function (prefix) {

   var self = this;
   return self._index[prefix];
};

ab.PrefixMap.prototype.set = function (prefix, uri) {

   var self = this;
   self._index[prefix] = uri;
   self._rindex[uri] = prefix;
};

ab.PrefixMap.prototype.setDefault = function (uri) {

   var self = this;
   self._index[""] = uri;
   self._rindex[uri] = "";
};

ab.PrefixMap.prototype.remove = function (prefix) {

   var self = this;
   var uri = self._index[prefix];
   if (uri) {
      delete self._index[prefix];
      delete self._rindex[uri];
   }
};

ab.PrefixMap.prototype.resolve = function (curie, pass) {

   var self = this;

   // skip if not a CURIE
   var i = curie.indexOf(":");
   if (i >= 0) {
      var prefix = curie.substring(0, i);
      if (self._index[prefix]) {
         return self._index[prefix] + curie.substring(i + 1);
      }
   }

   // either pass-through or null
   if (pass == true) {
      return curie;
   } else {
      return null;
   }
};

ab.PrefixMap.prototype.shrink = function (uri, pass) {

   var self = this;

   for (var i = uri.length; i > 0; i -= 1) {
      var u = uri.substring(0, i);
      var p = self._rindex[u];
      if (p) {
         return p + ":" + uri.substring(i);
      }
   }

   // either pass-through or null
   if (pass == true) {
      return uri;
   } else {
      return null;
   }
};


ab._MESSAGE_TYPEID_WELCOME        = 0;
ab._MESSAGE_TYPEID_PREFIX         = 1;
ab._MESSAGE_TYPEID_CALL           = 2;
ab._MESSAGE_TYPEID_CALL_RESULT    = 3;
ab._MESSAGE_TYPEID_CALL_ERROR     = 4;
ab._MESSAGE_TYPEID_SUBSCRIBE      = 5;
ab._MESSAGE_TYPEID_UNSUBSCRIBE    = 6;
ab._MESSAGE_TYPEID_PUBLISH        = 7;
ab._MESSAGE_TYPEID_EVENT          = 8;

ab.CONNECTION_CLOSED = 0;
ab.CONNECTION_LOST = 1;
ab.CONNECTION_RETRIES_EXCEEDED = 2;
ab.CONNECTION_UNREACHABLE = 3;
ab.CONNECTION_UNSUPPORTED = 4;
ab.CONNECTION_UNREACHABLE_SCHEDULED_RECONNECT = 5;
ab.CONNECTION_LOST_SCHEDULED_RECONNECT = 6;

ab._Deferred = when.defer;
//ab._Deferred = jQuery.Deferred;

ab._construct = function (url, protocols) {
   if ("WebSocket" in window) {
      // Chrome, MSIE, newer Firefox
      return new WebSocket(url, protocols);
   } else if ("MozWebSocket" in window) {
      // older versions of Firefox prefix the WebSocket object
      return new MozWebSocket(url, protocols);
   } else {
      return null;
   }
};

ab.Session = function (wsuri, onopen, onclose, options) {

   var self = this;

   self._wsuri = wsuri;
   self._options = options;
   self._websocket_onopen = onopen;
   self._websocket_onclose = onclose;

   self._websocket = null;
   self._websocket_connected = false;

   self._session_id = null;
   self._wamp_version = null;
   self._server = null;

   self._calls = {};
   self._subscriptions = {};
   self._prefixes = new ab.PrefixMap();

   self._txcnt = 0;
   self._rxcnt = 0;

   self._websocket = ab._construct(self._wsuri, [ab._subprotocol]);
   if (!self._websocket) {
      if (onclose !== undefined) {
         onclose(ab.CONNECTION_UNSUPPORTED);
         return;
      } else {
         throw ab.browserNotSupportedMessage;
      }
   }

   self._websocket.onmessage = function (e)
   {
      if (ab._debugws) {
         self._rxcnt += 1;
         console.group("WS Receive");
         console.info(self._wsuri + "  [" + self._session_id + "]");
         console.log(self._rxcnt);
         console.log(e.data);
         console.groupEnd();
      }

      var o = JSON.parse(e.data);
      if (o[1] in self._calls)
      {
         if (o[0] === ab._MESSAGE_TYPEID_CALL_RESULT) {

            var dr = self._calls[o[1]];
            var r = o[2];

            if (ab._debugrpc && dr._ab_callobj !== undefined) {
               console.group("WAMP Call", dr._ab_callobj[2]);
               console.timeEnd(dr._ab_tid);
               console.group("Arguments");
               for (var i = 3; i < dr._ab_callobj.length; i += 1) {
                  var arg = dr._ab_callobj[i];
                  if (arg !== undefined) {
                     console.log(arg);
                  } else {
                     break;
                  }
               }
               console.groupEnd();
               console.group("Result");
               console.log(r);
               console.groupEnd();
               console.groupEnd();
            }

            dr.resolve(r);
         }
         else if (o[0] === ab._MESSAGE_TYPEID_CALL_ERROR) {

            var de = self._calls[o[1]];
            var uri_ = o[2];
            var desc_ = o[3];
            var detail_ = o[4];

            if (ab._debugrpc && de._ab_callobj !== undefined) {
               console.group("WAMP Call", de._ab_callobj[2]);
               console.timeEnd(de._ab_tid);
               console.group("Arguments");
               for (var j = 3; j < de._ab_callobj.length; j += 1) {
                  var arg2 = de._ab_callobj[j];
                  if (arg2 !== undefined) {
                     console.log(arg2);
                  } else {
                     break;
                  }
               }
               console.groupEnd();
               console.group("Error");
               console.log(uri_);
               console.log(desc_);
               if (detail_ !== undefined) {
                  console.log(detail_);
               }
               console.groupEnd();
               console.groupEnd();
            }

            if (detail_ !== undefined) {
               de.reject({uri: uri_, desc: desc_, detail: detail_});
            } else {
               de.reject({uri: uri_, desc: desc_});
            }
         }
         delete self._calls[o[1]];
      }
      else if (o[0] === ab._MESSAGE_TYPEID_EVENT)
      {
         var subid = self._prefixes.resolve(o[1], true);
         if (subid in self._subscriptions) {

            var uri2 = o[1];
            var val = o[2];

            if (ab._debugpubsub) {
               console.group("WAMP Event");
               console.info(self._wsuri + "  [" + self._session_id + "]");
               console.log(uri2);
               console.log(val);
               console.groupEnd();
            }

            self._subscriptions[subid].forEach(function (callback) {

               callback(uri2, val);
            });
         }
         else {
            // ignore unsolicited event!
         }
      }
      else if (o[0] === ab._MESSAGE_TYPEID_WELCOME)
      {
         if (self._session_id === null) {
            self._session_id = o[1];
            self._wamp_version = o[2];
            self._server = o[3];

            if (ab._debugrpc || ab._debugpubsub) {
               console.group("WAMP Welcome");
               console.info(self._wsuri + "  [" + self._session_id + "]");
               console.log(self._wamp_version);
               console.log(self._server);
               console.groupEnd();
            }

            // only now that we have received the initial server-to-client
            // welcome message, fire application onopen() hook
            if (self._websocket_onopen !== null) {
               self._websocket_onopen();
            }
         } else {
            throw "protocol error (welcome message received more than once)";
         }
      }
   };

   self._websocket.onopen = function (e)
   {
      // check if we can speak WAMP!
      if (self._websocket.protocol !== ab._subprotocol) {

         if (typeof self._websocket.protocol === 'undefined') {
            // i.e. Safari does subprotocol negotiation (broken), but then
            // does NOT set the protocol attribute of the websocket object (broken)
            //
            if (ab._debugws) {
               console.group("WS Warning");
               console.info(self._wsuri);
               console.log("WebSocket object has no protocol attribute: WAMP subprotocol check skipped!");
               console.groupEnd();
            }
         }
         else if (self._options && self._options.skipSubprotocolCheck) {
            // WAMP subprotocol check disabled by session option
            //
            if (ab._debugws) {
               console.group("WS Warning");
               console.info(self._wsuri);
               console.log("Server does not speak WAMP, but subprotocol check disabled by option!");
               console.log(self._websocket.protocol);
               console.groupEnd();
            }
         } else {
            // we only speak WAMP .. if the server denied us this, we bail out.
            //
            self._websocket.close(1000, "server does not speak WAMP");
            throw "server does not speak WAMP (but '" + self._websocket.protocol + "' !)";
         }
      }
      if (ab._debugws) {
         console.group("WAMP Connect");
         console.info(self._wsuri);
         console.log(self._websocket.protocol);
         console.groupEnd();
      }
      self._websocket_connected = true;
   };

   self._websocket.onerror = function (e)
   {
      // FF fires this upon unclean closes
      // Chrome does not fire this
   };

   self._websocket.onclose = function (e)
   {
      if (ab._debugws) {
         if (self._websocket_connected) {
            console.log("Autobahn connection to " + self._wsuri + " lost (code " + e.code + ", reason '" + e.reason + "', wasClean " + e.wasClean + ").");
         } else {
            console.log("Autobahn could not connect to " + self._wsuri + " (code " + e.code + ", reason '" + e.reason + "', wasClean " + e.wasClean + ").");
         }
      }

      // fire app callback
      if (self._websocket_onclose !== undefined) {
         if (self._websocket_connected) {
            if (e.wasClean) {
               // connection was closed cleanly (closing HS was performed)
               self._websocket_onclose(ab.CONNECTION_CLOSED);
            } else {
               // connection was closed uncleanly (lost without closing HS)
               self._websocket_onclose(ab.CONNECTION_LOST);
            }
         } else {
            // connection could not be established in the first place
            self._websocket_onclose(ab.CONNECTION_UNREACHABLE);
         }
      }

      // cleanup - reconnect requires a new session object!
      self._websocket_connected = false;
      self._wsuri = null;
      self._websocket_onopen = null;
      self._websocket_onclose = null;
      self._websocket = null;
   };
};


ab.Session.prototype._send = function (msg) {

   var self = this;

   if (!self._websocket_connected) {
      throw "Autobahn not connected";
   }

   var rmsg = JSON.stringify(msg);
   self._websocket.send(rmsg);
   self._txcnt += 1;

   if (ab._debugws) {
      console.group("WS Send");
      console.info(self._wsuri + "  [" + self._session_id + "]");
      console.log(self._txcnt);
      console.log(rmsg);
      console.groupEnd();
   }
};


ab.Session.prototype.close = function () {

   var self = this;

   if (self._websocket_connected) {
      self._websocket.close();
   } else {
      //throw "Autobahn not connected";
   }
};


ab.Session.prototype.sessionid = function () {

   var self = this;
   return self._session_id;
};


ab.Session.prototype.shrink = function (uri, pass) {

   var self = this;
   if (pass === undefined) pass = true;
   return self._prefixes.shrink(uri, pass);
};


ab.Session.prototype.resolve = function (curie, pass) {

   var self = this;
   if (pass === undefined) pass = true;
   return self._prefixes.resolve(curie, pass);
};


ab.Session.prototype.prefix = function (prefix, uri) {

   var self = this;

/*
   if (self._prefixes.get(prefix) !== undefined) {
      throw "prefix '" + prefix + "' already defined";
   }
*/

   self._prefixes.set(prefix, uri);

   if (ab._debugrpc || ab._debugpubsub) {
      console.group("WAMP Prefix");
      console.info(self._wsuri + "  [" + self._session_id + "]");
      console.log(prefix);
      console.log(uri);
      console.groupEnd();
   }

   var msg = [ab._MESSAGE_TYPEID_PREFIX, prefix, uri];
   self._send(msg);
};


ab.Session.prototype.call = function () {

   var self = this;

   var d = new ab._Deferred();
   var callid;
   while (true) {
      callid = ab._newid();
      if (!(callid in self._calls)) {
         break;
      }
   }
   self._calls[callid] = d;

   var procuri = self._prefixes.shrink(arguments[0], true);
   var obj = [ab._MESSAGE_TYPEID_CALL, callid, procuri];
   for (var i = 1; i < arguments.length; i += 1) {
      obj.push(arguments[i]);
   }

   self._send(obj);

   if (ab._debugrpc) {
      d._ab_callobj = obj;
      d._ab_tid = self._wsuri + "  [" + self._session_id + "][" + callid + "]";
      console.time(d._ab_tid);
      console.info();
   }

   return d;
};


ab.Session.prototype.subscribe = function (topicuri, callback) {

   var self = this;

   // subscribe by sending WAMP message when topic not already subscribed
   //
   var rtopicuri = self._prefixes.resolve(topicuri, true);
   if (!(rtopicuri in self._subscriptions)) {

      if (ab._debugpubsub) {
         console.group("WAMP Subscribe");
         console.info(self._wsuri + "  [" + self._session_id + "]");
         console.log(topicuri);
         console.log(callback);
         console.groupEnd();
      }

      var msg = [ab._MESSAGE_TYPEID_SUBSCRIBE, topicuri];
      self._send(msg);

      self._subscriptions[rtopicuri] = [];
   }

   // add callback to event listeners list if not already in list
   //
   var i = self._subscriptions[rtopicuri].indexOf(callback);
   if (i === -1) {
      self._subscriptions[rtopicuri].push(callback);
   }
   else {
      throw "callback " + callback + " already subscribed for topic " + rtopicuri;
   }
};


ab.Session.prototype.unsubscribe = function (topicuri, callback) {

   var self = this;

   var rtopicuri = self._prefixes.resolve(topicuri, true);
   if (!(rtopicuri in self._subscriptions)) {
      throw "not subscribed to topic " + rtopicuri;
   }
   else {
      var removed;
      if (callback !== undefined) {
         var idx = self._subscriptions[rtopicuri].indexOf(callback);
         if (idx !== -1) {
            removed = callback;
            self._subscriptions[rtopicuri].splice(idx, 1);
         }
         else {
            throw "no callback " + callback + " subscribed on topic " + rtopicuri;
         }
      }
      else {
         removed = self._subscriptions[rtopicuri].slice();
         self._subscriptions[rtopicuri] = [];
      }

      if (self._subscriptions[rtopicuri].length === 0) {

         delete self._subscriptions[rtopicuri];

         if (ab._debugpubsub) {
            console.group("WAMP Unsubscribe");
            console.info(self._wsuri + "  [" + self._session_id + "]");
            console.log(topicuri);
            console.log(removed);
            console.groupEnd();
         }

         var msg = [ab._MESSAGE_TYPEID_UNSUBSCRIBE, topicuri];
         self._send(msg);
      }
   }
};


ab.Session.prototype.publish = function () {

   var self = this;

   var topicuri = arguments[0];
   var event = arguments[1];

   var excludeMe = null;
   var exclude = null;
   var eligible = null;

   var msg = null;

   if (arguments.length > 3) {

      if (!(arguments[2] instanceof Array)) {
         throw "invalid argument type(s)";
      }
      if (!(arguments[3] instanceof Array)) {
         throw "invalid argument type(s)";
      }

      exclude = arguments[2];
      eligible = arguments[3];
      msg = [ab._MESSAGE_TYPEID_PUBLISH, topicuri, event, exclude, eligible];

   } else if (arguments.length > 2) {

      if (typeof(arguments[2]) === 'boolean') {

         excludeMe = arguments[2];
         msg = [ab._MESSAGE_TYPEID_PUBLISH, topicuri, event, excludeMe];

      } else if (arguments[2] instanceof Array) {

         exclude = arguments[2];
         msg = [ab._MESSAGE_TYPEID_PUBLISH, topicuri, event, exclude];

      } else {
         throw "invalid argument type(s)";
      }

   } else {

      msg = [ab._MESSAGE_TYPEID_PUBLISH, topicuri, event];
   }

   if (ab._debugpubsub) {
      console.group("WAMP Publish");
      console.info(self._wsuri + "  [" + self._session_id + "]");
      console.log(topicuri);
      console.log(event);

      if (excludeMe !== null) {
         console.log(excludeMe);
      } else {
         if (exclude !== null) {
            console.log(exclude);
            if (eligible !== null) {
               console.log(eligible);
            }
         }
      }
      console.groupEnd();
   }

   self._send(msg);
};


// allow both 2-party and 3-party authentication/authorization
// for 3-party: let C sign, but let both the B and C party authorize

ab.Session.prototype.authreq = function (appkey, extra) {
   return this.call("http://api.wamp.ws/procedure#authreq", appkey, extra);
};

ab.Session.prototype.authsign = function (challenge, secret) {
   if (!secret) {
      secret = "";
   }
   return Crypto.util.bytesToBase64(Crypto.HMAC(Crypto.SHA256, challenge, secret, { asBytes: true }));
};

ab.Session.prototype.auth = function (signature) {
   return this.call("http://api.wamp.ws/procedure#auth", signature);
};


ab._connect = function (peer) {

   // establish session to WAMP server
   var sess = new ab.Session(peer.wsuri,

      // fired when session has been opened
      function() {

         peer.connects += 1;
         peer.retryCount = 0;

         // we are connected .. do awesome stuff!
         peer.onConnect(sess);
      },

      // fired when session has been closed
      function(code) {

         switch (code) {

            case ab.CONNECTION_CLOSED:
               // the session was closed by the app
               peer.onHangup(code, "Connection was closed properly - done.");
               break;

            case ab.CONNECTION_UNSUPPORTED:
               // fatal: we miss our WebSocket object!
               peer.onHangup(code, "Browser does not support WebSocket.");
               break;

            case ab.CONNECTION_UNREACHABLE:

               peer.retryCount += 1;

               if (peer.connects == 0) {

                  // the connection could not be established in the first place
                  // which likely means invalid server WS URI or such things
                  peer.onHangup(code, "Connection could not be established.");

               } else {

                  // the connection was established at least once successfully,
                  // but now lost .. sane thing is to try automatic reconnects
                  if (peer.retryCount <= peer.options.maxRetries) {

                     // notify the app of scheduled reconnect
                     var stop = peer.onHangup(ab.CONNECTION_UNREACHABLE_SCHEDULED_RECONNECT,
                                              "Connection unreachable - scheduled reconnect to occur in " + (peer.options.retryDelay / 1000) + " second(s).",
                                             {delay: peer.options.retryDelay,
                                              retries: peer.retryCount,
                                              maxretries: peer.options.maxRetries});

                     if (!stop) {
                        console.log("Connection unreachable - retrying (" + peer.retryCount + ") ..");
                        window.setTimeout(ab._connect, peer.options.retryDelay, peer);
                     } else {
                        console.log("Connection unreachable - retrying stopped by app");
                        peer.onHangup(ab.CONNECTION_RETRIES_EXCEEDED, "Number of connection retries exceeded.");
                     }

                  } else {
                     peer.onHangup(ab.CONNECTION_RETRIES_EXCEEDED, "Number of connection retries exceeded.");
                  }
               }
               break;

            case ab.CONNECTION_LOST:

               peer.retryCount += 1;

               if (peer.retryCount <= peer.options.maxRetries) {

                  // notify the app of scheduled reconnect
                  var stop = peer.onHangup(ab.CONNECTION_LOST_SCHEDULED_RECONNECT,
                                           "Connection lost - scheduled reconnect to occur in " + (peer.options.retryDelay / 1000) + " second(s).",
                                          {delay: peer.options.retryDelay,
                                           retries: peer.retryCount,
                                           maxretries: peer.options.maxRetries});

                  if (!stop) {
                     console.log("Connection lost - retrying (" + peer.retryCount + ") ..");
                     window.setTimeout(ab._connect, peer.options.retryDelay, peer);
                  } else {
                     console.log("Connection lost - retrying stopped by app");
                     peer.onHangup(ab.CONNECTION_RETRIES_EXCEEDED, "Connection lost.");
                  }
               } else {
                  peer.onHangup(ab.CONNECTION_RETRIES_EXCEEDED, "Connection lost.");
               }
               break;

            default:
               throw "unhandled close code in ab._connect";
               break;
         }
      },

      peer.options // forward options to session class for specific WS/WAMP options
   );
};


ab.connect = function (wsuri, onconnect, onhangup, options) {

   peer = {};
   peer.wsuri = wsuri;

   if (!options) {
      peer.options = {};
   } else {
      peer.options = options;
   }

   if (peer.options.retryDelay == undefined) {
      peer.options.retryDelay = 5000;
   }

   if (peer.options.maxRetries == undefined) {
      peer.options.maxRetries = 10;
   }

   if (peer.options.skipSubprotocolCheck == undefined) {
      peer.options.skipSubprotocolCheck = false;
   }

   if (!onconnect) {
      throw "onConnect handler required!";
   } else {
      peer.onConnect = onconnect;
   }

   if (!onhangup) {
      peer.onHangup = function (code, reason) {
         console.log(reason);
      }
   } else {
      peer.onHangup = onhangup;
   }

   peer.connects = 0; // total number of successful connects
   peer.retryCount = 0; // number of retries since last successful connect

   ab._connect(peer);
};

ab._UA_FIREFOX = new RegExp(".*Firefox/([0-9+]*).*")
ab._UA_CHROME = new RegExp(".*Chrome/([0-9+]*).*")
ab._UA_CHROMEFRAME = new RegExp(".*chromeframe/([0-9]*).*")
ab._UA_WEBKIT = new RegExp(".*AppleWebKit/([0-9+\.]*)\w*.*")
ab._UA_WEBOS = new RegExp(".*webOS/([0-9+\.]*)\w*.*")

ab._matchRegex = function(s, r) {
	var m = r.exec(s)
	if (m) return m[1]
	return m
};

ab.lookupWsSupport = function() {
	var ua = navigator.userAgent;

	// Internet Explorer
	if (ua.indexOf("MSIE") > -1) {
		if (ua.indexOf("MSIE 10") > -1)
			return [true,true,true]
		if (ua.indexOf("chromeframe") > -1) {
			var v = parseInt(ab._matchRegex(ua, ab._UA_CHROMEFRAME))
			if (v >= 14)
				return [true,false,true]
			return [false,false,false]
		}
		if (ua.indexOf("MSIE 8") > -1 || ua.indexOf("MSIE 9") > -1)
			return [true,true,true]
		return [false,false,false]
	}

	// Firefox
	else if (ua.indexOf("Firefox") > -1) {
		var v = parseInt(ab._matchRegex(ua, ab._UA_FIREFOX))
		if (v) {
			if (v >= 7)
				return [true,false,true]
			if (v >= 3)
				return [true,true,true]
			return [false,false,true]
		}
		return [false,false,true]

	}

	// Safari
	else if (ua.indexOf("Safari") > -1 && ua.indexOf("Chrome") == -1) {
		var v = ab._matchRegex(ua, ab._UA_WEBKIT)
		if (v) {
			if (ua.indexOf("Windows") > -1 && v == "534+") // Not sure about this test ~RMH
				return [true,false,true]
			if (ua.indexOf("Macintosh") > -1) {
				v = v.replace("+","").split(".")
				if ((parseInt(v[0]) == 535 && parseInt(v[1]) >= 24) || parseInt(v[0]) > 535)
					return [true,false,true]
			}
			if (ua.indexOf("webOS") > -1) {
				v = ab._matchRegex(ua, ab._UA_WEBOS).split(".")
				if (parseInt(v[0]) == 2)
					return [false,true,true]
				return [false,false,false]
			}
			return [true,true,true]
		}
		return [false,false,false]
	}

	// Chrome
	else if (ua.indexOf("Chrome") > -1) {
		var v = parseInt(ab._matchRegex(ua, ab._UA_CHROME))
		if (v) {
			if (v >= 14)
				return [true,false,true]
			if (v >= 4)
				return [true,true,true]
			return [false,false,true]
		}
		return [false,false,false]
	}

	// Android
	else if (ua.indexOf("Android") > -1) {
		// Firefox Mobile
		if (ua.indexOf("Firefox") > -1)
			return [true,false,true]
		// Chrome for Android
		else if (ua.indexOf("CrMo") > -1)
			return [true,false,true]
		// Opera Mobile
		else if (ua.indexOf("Opera") > -1)
			return [false,false,true]
		// Android Browser
		else if (ua.indexOf("CrMo") > -1)
			return [true,true,true]
		return [false,false,false]
	}

	// iOS
	else if (ua.indexOf("iPhone") > -1 || ua.indexOf("iPad") > -1 || ua.indexOf("iPod") > -1)
		return [false,false,true]

	// Unidentified
	return [false,false,false]


};

