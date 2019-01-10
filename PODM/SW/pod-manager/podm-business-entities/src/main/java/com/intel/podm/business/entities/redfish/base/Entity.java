/*
 * Copyright (c) 2015-2017 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.intel.podm.business.entities.redfish.base;


import com.intel.podm.business.entities.listeners.EntityListenerImpl;

import javax.persistence.Column;
import javax.persistence.EntityListeners;
import javax.persistence.GeneratedValue;
import javax.persistence.MappedSuperclass;
import javax.persistence.PreRemove;
import javax.persistence.Version;
import java.net.URI;
import java.util.Collection;
import java.util.Iterator;
import java.util.Objects;
import java.util.function.Consumer;
import java.util.function.Predicate;

import static java.lang.String.format;
import static java.util.Objects.hash;
import static javax.persistence.GenerationType.IDENTITY;

@MappedSuperclass
@EntityListeners(EntityListenerImpl.class)
public abstract class Entity {
    protected static final String ENTITY_ID_NUMERIC_COLUMN_DEFINITION = "bigserial";
    protected static final String ENTITY_ID_STRING_COLUMN_DEFINITION = "text";

    @javax.persistence.Id
    @GeneratedValue(strategy = IDENTITY)
    @Column(name = "id")
    private long id;

    @Version
    @Column(name = "version", columnDefinition = "integer DEFAULT 0", nullable = false)
    private long version;

    @Column(name = "event_source_context")
    private URI eventSourceContext;

    public long getPrimaryKey() {
        return id;
    }

    public abstract void preRemove();

    public abstract boolean containedBy(Entity possibleParent);

    @PreRemove
    public void unlinkRelations() {
        preRemove();
    }


    public URI getEventSourceContext() {
        return eventSourceContext;
    }

    public void setEventSourceContext(URI eventSourceContext) {
        this.eventSourceContext = eventSourceContext;
    }

    protected boolean isContainedBy(Entity possibleParent, Entity realParent) {
        return possibleParent != null && Objects.equals(realParent, possibleParent);
    }

    protected boolean isContainedBy(Entity possibleParent, Collection<? extends Entity> realParents) {
        if (possibleParent == null || realParents == null) {
            return false;
        }

        return realParents.stream().filter(realParent -> isContainedBy(possibleParent, realParent)).count() > 0;
    }

    protected <T extends Entity> void unlinkCollection(Collection<T> entities, Consumer<T> unlinkConsumer, Predicate<T> predicate) {
        //TODO: think how remove and clean relations in loop in more efficient way (this prevents from ConcurrentModificationException)
        Iterator<T> iterator = entities.iterator();
        while (iterator.hasNext()) {
            T entity = iterator.next();
            if (predicate.test(entity)) {
                unlinkConsumer.accept(entity);
                iterator = entities.iterator();
            }
        }
    }

    protected <T extends Entity> void unlinkCollection(Collection<T> entities, Consumer<T> unlinkConsumer) {
        unlinkCollection(entities, unlinkConsumer, x -> true);
    }

    @Override
    public int hashCode() {
        return hash(id);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (o == null || (!(o instanceof Entity))) {
            return false;
        }
        Entity that = (Entity) o;
        return Objects.equals(getPrimaryKey(), that.getPrimaryKey());
    }

    @Override
    public String toString() {
        return format("Entity {clazz=%s, primaryKey=%d}", getClass().getSimpleName(), getPrimaryKey());
    }
}
